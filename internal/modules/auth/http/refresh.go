package http

import (
	"time"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"

	"github.com/gofiber/fiber/v2"
)

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
	DeviceName   string `json:"device_name"`
}

func RefreshHandler(
	sessions domain.SessionRepo,
	userRepo domain.UserRepo, // <— добавили
	jwtMgr *security.JWTManager,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req refreshReq
		if err := c.BodyParser(&req); err != nil || req.RefreshToken == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректный запрос",
			})
		}

		hash := security.HashToken(req.RefreshToken)
		s, err := sessions.FindByRefreshHash(hash)
		if err != nil || s == nil || s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "INVALID_REFRESH",
				"message":    "Невалидный или истёкший refresh_token",
			})
		}

		// инвалидируем старый
		_ = sessions.Revoke(s.ID, s.UserID)

		// создаём новый refresh → новая сессия
		rt, _, err := security.IssueRefresh()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось создать refresh",
			})
		}
		rth := security.HashToken(rt)
		ip := c.IP()
		ua := c.Get("User-Agent")
		dev := req.DeviceName

		newSess, err := sessions.Create(domain.Session{
			UserID:           s.UserID,
			RefreshTokenHash: rth,
			DeviceName:       &dev,
			IPAddress:        &ip,
			UserAgent:        &ua,
			ExpiresAt:        time.Now().Add(30 * 24 * time.Hour),
		})
		if err != nil || newSess == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось создать сессию",
			})
		}

		// достаём роль пользователя
		u, err := userRepo.GetByID(s.UserID)
		if err != nil || u == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось получить пользователя",
			})
		}

		at, exp, err := jwtMgr.IssueAccess(s.UserID, string(u.Role), newSess.ID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось создать access_token",
			})
		}

		return c.JSON(fiber.Map{
			"message":       "Токены обновлены",
			"access_token":  at,
			"refresh_token": rt,
			"expires_at":    exp.UTC().Format(time.RFC3339),
		})
	}
}
