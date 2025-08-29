package http

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
)

func GetProfileHandler(userRepo domain.UserRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}

		u, err := userRepo.GetByID(uid)
		if err != nil || u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error_code": "NOT_FOUND",
				"message":    "Пользователь не найден",
			})
		}

		return c.JSON(fiber.Map{
			"user_id":    u.ID,
			"email":      u.Email,
			"first_name": u.FirstName,
			"last_name":  u.LastName,
			"role":       u.Role,
			"phone":      u.Phone,
			"created_at": u.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
}
