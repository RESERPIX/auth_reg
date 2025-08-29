package http

import (
	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

type deleteReq struct {
	Password string `json:"password"`
}

func DeleteUserHandler(userRepo domain.UserRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}

		var req deleteReq
		if err := c.BodyParser(&req); err != nil || req.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Пароль обязателен",
			})
		}

		u, err := userRepo.GetByID(uid)
		if err != nil || u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error_code": "NOT_FOUND",
				"message":    "Пользователь не найден",
			})
		}

		ok, _ := security.CheckPassword(*u.PasswordHash, req.Password)
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_PASSWORD",
				"message":    "Некорректный пароль",
			})
		}

		if err := userRepo.Delete(uid); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось удалить аккаунт",
			})
		}
		return c.JSON(fiber.Map{"message": "Аккаунт успешно удалён"})
	}
}
