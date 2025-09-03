package http

import (
	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

type disable2FAReq struct {
	Password string `json:"password"`
}

func Disable2FAHandler(userRepo domain.UserRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}

		var req disable2FAReq
		if err := c.BodyParser(&req); err != nil || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Пароль обязателен",
			})
		}

		u, err := userRepo.GetByID(uid)
		if err != nil || u == nil || u.PasswordHash == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_STATE",
				"message":    "Невозможно отключить 2FA",
			})
		}

		ok, _ := security.CheckPassword(*u.PasswordHash, req.Password)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_PASSWORD",
				"message":    "Неверный пароль",
			})
		}

		if err := userRepo.SetTwoFA(uid, false); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось отключить 2FA",
			})
		}

		return c.JSON(fiber.Map{"message": "2FA отключена"})
	}
}
