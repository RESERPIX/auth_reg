package http

import (
	"auth/internal/modules/auth/domain"
	"github.com/gofiber/fiber/v2"
)

func Enable2FAHandler(userRepo domain.UserRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}
		if err := userRepo.SetTwoFA(uid, true); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось включить 2FA",
			})
		}
		return c.JSON(fiber.Map{"message": "2FA включена"})
	}
}
