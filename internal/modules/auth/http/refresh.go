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

func RefreshHandler(sessions domain.SessionRepo, jwtMgr *security.JWTManager) fiber.Handler {
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
		if err != nil || s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "INVALID_REFRESH",
				"message":    "Невалидный или истёкший refresh_token",
			})
		}

		// инвалидируем старый
		_ = sessions.Revoke(s.ID, s.UserID)

		// генерируем новый refresh
		rt, _, _ := security.IssueRefresh()
		rth := security.HashToken(rt)
		ip := c.IP()
		ua := c.Get("User-Agent")
		dev := req.DeviceName
		newSess, _ := sessions.Create(domain.Session{
			UserID:           s.UserID,
			RefreshTokenHash: rth,
			DeviceName:       &dev,
			IPAddress:        &ip,
			UserAgent:        &ua,
			ExpiresAt:        time.Now().Add(30 * 24 * time.Hour),
		})

		at, exp, _ := jwtMgr.IssueAccess(s.UserID, "journalist", newSess.ID) // роль можно достать из UserRepo, если нужно

		return c.JSON(fiber.Map{
			"message":       "Токены обновлены",
			"access_token":  at,
			"refresh_token": rt,
			"expires_at":    exp.UTC().Format(time.RFC3339),
		})
	}
}
