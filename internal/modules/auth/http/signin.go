package http

import (
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/notify"
	"auth/internal/platform/security"
)

type signInReq struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceName string `json:"device_name"`
}

type signInResp struct {
	Message      string `json:"message"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Requires2FA  bool   `json:"requires_2fa"`
}

// Добавим mailer в хендлер через замыкание
func SignInHandler(
	userRepo domain.UserRepo,
	sessions domain.SessionRepo,
	codeRepo domain.CodeRepo, // ← было VerificationCodeRepo
	mailer *notify.Mailer, // ← было domain.Mailer
	jwtMgr *security.JWTManager,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req signInReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}

		req.Email = strings.ToLower(strings.TrimSpace(req.Email))

		u, err := userRepo.GetByEmail(req.Email)
		if err != nil || u == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_CREDENTIALS",
				"message":    "Некорректный email или пароль",
			})
		}

		// Проверка блокировки
		if u.IsBlocked {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error_code": "ACCOUNT_BLOCKED",
				"message":    "Аккаунт заблокирован",
			})
		}

		// Проверка подтверждения email
		if !u.EmailConfirmed {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "EMAIL_NOT_CONFIRMED",
				"message":    "Подтвердите email перед входом",
			})
		}

		// Проверка пароля
		ok, _ := security.CheckPassword(*u.PasswordHash, req.Password)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_CREDENTIALS",
				"message":    "Некорректный email или пароль",
			})
		}

		// 🔐 Проверка: включена ли 2FA?
		if u.TwoFAEnabled {
			code, err := security.RandomDigits(6)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error_code": "SERVER_ERROR",
					"message":    "Не удалось сгенерировать код",
				})
			}

			// Сохраняем код для последующей проверки
			err = codeRepo.Save(domain.VerificationCode{
				UserID:    u.ID,
				Kind:      domain.Code2FA,
				Code:      code,
				ExpiresAt: time.Now().Add(10 * time.Minute),
				SentTo:    u.Email,
			})
			if err != nil {
				log.Printf("failed to save 2FA code: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error_code": "SERVER_ERROR",
					"message":    "Не удалось сохранить код подтверждения",
				})
			}

			// Отправляем код на email (асинхронно)
			if mailer != nil {
				go func() {
					if err := mailer.Send2FACode(c.Context(), u.Email, code); err != nil {
						log.Printf("failed to send 2FA email to %s: %v", u.Email, err)
					}
				}()
			}

			// Возвращаем ответ: 2FA требуется, токены не выданы
			return c.JSON(signInResp{
				Message:     "Требуется подтверждение двухфакторной аутентификации",
				Requires2FA: true,
			})
		}

		// 🟢 Если 2FA НЕ включена — продолжаем обычный вход

		// Генерируем refresh token
		rt, _, err := security.IssueRefresh()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось создать refresh_token",
			})
		}

		// Хешируем refresh token для хранения
		rth := security.HashToken(rt)
		ip := c.IP()
		ua := c.Get("User-Agent")
		dev := req.DeviceName

		s := domain.Session{
			UserID:           u.ID,
			RefreshTokenHash: rth,
			DeviceName:       &dev,
			IPAddress:        &ip,
			UserAgent:        &ua,
		}

		sess, err := sessions.Create(s)
		if err != nil {
			log.Printf("create session error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось создать сессию",
			})
		}

		// Генерируем access token с включённым session_id (sid)
		at, exp, err := jwtMgr.IssueAccess(u.ID, string(u.Role), sess.ID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось создать access_token",
			})
		}

		// Возвращаем токены
		return c.JSON(signInResp{
			Message:      "Вход успешен",
			AccessToken:  at,
			RefreshToken: rt,
			ExpiresAt:    exp.UTC().Format(time.RFC3339),
			Requires2FA:  false,
		})
	}
}
