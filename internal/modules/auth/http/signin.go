package http

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
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

func SignInHandler(userRepo domain.UserRepo, sessions domain.SessionRepo, jwtMgr *security.JWTManager) fiber.Handler {
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

		// проверка блокировки
		if u.IsBlocked {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error_code": "ACCOUNT_BLOCKED",
				"message":    "Аккаунт заблокирован",
			})
		}

		// проверка подтверждения email
		if !u.EmailConfirmed {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "EMAIL_NOT_CONFIRMED",
				"message":    "Подтвердите email перед входом",
			})
		}

		// проверка пароля
		ok, _ := security.CheckPassword(*u.PasswordHash, req.Password)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_CREDENTIALS",
				"message":    "Некорректный email или пароль",
			})
		}

		// пока 2FA отключена → всегда false
		requires2FA := false
		if requires2FA {
			return c.JSON(signInResp{
				Message:     "Вход успешен",
				Requires2FA: true,
			})
		}

		rt, _, err := security.IssueRefresh()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось создать refresh_token",
			})
		}

		// TODO: сохранить refresh в SessionRepo (in-memory пока не используем)

		// сохраняем сессию
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
		sess, err := sessions.Create(s) // ← важный шаг: сначала создаём сессию
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось создать сессию",
			})
		}

		// 2) теперь выпускаем access-токен с клеймом sid = sess.ID
		at, exp, err := jwtMgr.IssueAccess(u.ID, string(u.Role), sess.ID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось создать access_token",
			})
		}

		return c.JSON(signInResp{
			Message:      "Вход успешен",
			AccessToken:  at,
			RefreshToken: rt,
			ExpiresAt:    exp.UTC().Format(time.RFC3339),
			Requires2FA:  false,
		})
	}
}
