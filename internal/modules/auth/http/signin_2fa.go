package http

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

type signIn2FAReq struct {
	Email      string `json:"email"`
	Code       string `json:"code"`
	DeviceName string `json:"device_name"`
}

func SignIn2FAHandler(
	userRepo domain.UserRepo,
	codeRepo domain.CodeRepo,
	sessions domain.SessionRepo,
	jwtMgr *security.JWTManager,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req signIn2FAReq
		if err := c.BodyParser(&req); err != nil || len(req.Code) != 6 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}

		u, err := userRepo.GetByEmail(req.Email)
		if err != nil || u == nil || !u.TwoFAEnabled {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_STATE",
				"message":    "Пользователь не найден или 2FA не включена",
			})
		}

		// проверяем код
		if _, err := codeRepo.Consume(u.ID, domain.Code2FA, req.Code); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_CODE",
				"message":    "Некорректный или истёкший код",
			})
		}

		// создаём refresh + сессию
		rt, _, err := security.IssueRefresh()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось создать refresh",
			})
		}
		rth := security.HashToken(rt)
		ip, ua, dev := c.IP(), c.Get("User-Agent"), req.DeviceName
		sess, err := sessions.Create(domain.Session{
			UserID:           u.ID,
			RefreshTokenHash: rth,
			DeviceName:       &dev,
			IPAddress:        &ip,
			UserAgent:        &ua,
			ExpiresAt:        time.Now().Add(30 * 24 * time.Hour),
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось создать сессию",
			})
		}

		// создаём access
		at, exp, err := jwtMgr.IssueAccess(u.ID, string(u.Role), sess.ID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось создать access_token",
			})
		}

		return c.JSON(fiber.Map{
			"message":       "Вход завершён",
			"access_token":  at,
			"refresh_token": rt,
			"expires_at":    exp.UTC().Format(time.RFC3339),
			"requires_2fa":  false,
		})
	}
}
