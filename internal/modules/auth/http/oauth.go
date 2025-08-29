package http

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

type oauthReq struct {
	AccessToken string `json:"access_token"`
	DeviceName  string `json:"device_name"`
}

func OAuthSignInHandler(userRepo domain.UserRepo, sessions domain.SessionRepo, jwtMgr *security.JWTManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		provider := strings.ToLower(c.Params("provider"))
		if provider == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_PROVIDER",
				"message":    "Не указан провайдер",
			})
		}

		var req oauthReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}

		email, err := security.VerifyOAuthToken(provider, req.AccessToken)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_TOKEN",
				"message":    "Некорректный OAuth-токен",
			})
		}

		// ищем пользователя
		u, _ := userRepo.GetByEmail(email)
		if u == nil {
			// создаем нового
			u, _ = userRepo.Create(domain.CreateUserParams{
				Email:        email,
				FirstName:    provider,
				LastName:     "user",
				Role:         domain.RoleJournalist,
				PasswordHash: nil, // пароль не задаём
			})
			u.EmailConfirmed = true
			u.Providers = append(u.Providers, provider)
		} else {
			// добавляем провайдера, если ещё нет
			found := false
			for _, p := range u.Providers {
				if p == provider {
					found = true
					break
				}
			}
			if !found {
				u.Providers = append(u.Providers, provider)
			}
		}

		// создаем сессию
		rt, _, _ := security.IssueRefresh()
		rth := security.HashToken(rt)
		ip := c.IP()
		ua := c.Get("User-Agent")
		dev := req.DeviceName
		sess, _ := sessions.Create(domain.Session{
			UserID:           u.ID,
			RefreshTokenHash: rth,
			DeviceName:       &dev,
			IPAddress:        &ip,
			UserAgent:        &ua,
		})

		at, exp, _ := jwtMgr.IssueAccess(u.ID, string(u.Role), sess.ID)

		return c.JSON(fiber.Map{
			"message":       "Вход через провайдера успешен",
			"access_token":  at,
			"refresh_token": rt,
			"expires_at":    exp.UTC().Format(time.RFC3339),
		})
	}
}
