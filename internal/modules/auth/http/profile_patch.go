package http

import (
	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
)

type updateProfileReq struct {
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Phone     *string `json:"phone"`
}

func UpdateProfileHandler(userRepo domain.UserRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}

		var req updateProfileReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}

		if err := userRepo.UpdateProfile(uid, req.FirstName, req.LastName, req.Phone); err != nil {
			if err.Error() == "not_found" {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error_code": "NOT_FOUND",
					"message":    "Пользователь не найден",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось обновить профиль",
			})
		}
		return c.JSON(fiber.Map{"message": "Профиль успешно обновлён"})
	}
}
