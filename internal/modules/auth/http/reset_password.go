package http

import (
	"net/mail"
	"strings"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

type resetReq struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func ResetPasswordHandler(userRepo domain.UserRepo, codeRepo domain.CodeRepo, sessions domain.SessionRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req resetReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_FIELDS", "message": "Некорректные данные"})
		}
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		req.Code = strings.TrimSpace(req.Code)

		if _, err := mail.ParseAddress(req.Email); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_EMAIL", "message": "Некорректный формат email"})
		}
		if len(req.Code) != 6 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_CODE", "message": "Некорректный код восстановления"})
		}
		if len(req.NewPassword) < 8 || len(req.NewPassword) > 50 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_PASSWORD", "message": "Пароль должен быть от 8 до 50 символов"})
		}

		u, err := userRepo.GetByEmail(req.Email)
		if err != nil || u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error_code": "NOT_FOUND", "message": "Пользователь не найден"})
		}

		if _, err := codeRepo.Consume(u.ID, domain.CodeReset, req.Code); err != nil {
			// у нас есть разделение на INVALID/EXPIRED в памяти — отразим:
			if err.Error() == "code_expired" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "CODE_EXPIRED", "message": "Код восстановления истёк"})
			}
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_CODE", "message": "Некорректный код восстановления"})
		}

		hash, err := security.HashPassword(req.NewPassword)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error_code": "SERVER_ERROR", "message": "Не удалось обработать пароль"})
		}
		if err := userRepo.UpdatePassword(u.ID, hash); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error_code": "SERVER_ERROR", "message": "Не удалось сбросить пароль"})
		}

		// Сбросить все активные сессии (UC-3, шаг 11)
		_, _ = sessions.RevokeAll(u.ID)

		return c.JSON(fiber.Map{"message": "Пароль успешно сброшен"})
	}
}
