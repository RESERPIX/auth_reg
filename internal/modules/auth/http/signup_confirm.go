package http

import (
	"net/mail"
	"strings"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/modules/auth/infra"
)

type confirmReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type confirmResp struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

func SignUpConfirmHandler(userRepo domain.UserRepo, codeRepo domain.CodeRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req confirmReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}

		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		req.Code = strings.TrimSpace(req.Code)

		if req.Email == "" || req.Code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Email и код обязательны",
			})
		}
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_EMAIL",
				"message":    "Некорректный формат email",
			})
		}
		if len(req.Code) != 6 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_CODE",
				"message":    "Некорректный код подтверждения",
			})
		}

		// находим пользователя
		u, err := userRepo.GetByEmail(req.Email)
		if err != nil || u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error_code": "NOT_FOUND",
				"message":    "Пользователь не найден",
			})
		}

		// пробуем погасить код
		if _, err := codeRepo.Consume(u.ID, domain.CodeSignup, req.Code); err != nil {
			switch err {
			case infra.ErrCodeExpired:
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error_code": "CODE_EXPIRED",
					"message":    "Код подтверждения истёк",
				})
			default:
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error_code": "INVALID_CODE",
					"message":    "Некорректный код подтверждения",
				})
			}
		}

		// помечаем email подтверждённым
		if err := userRepo.ConfirmEmail(u.ID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось подтвердить email",
			})
		}

		return c.JSON(confirmResp{
			Message: "Email успешно подтверждён",
			UserID:  u.ID,
		})
	}
}
