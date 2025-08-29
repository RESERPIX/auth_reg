package http

import (
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

func ForgotPasswordResendHandler(userRepo domain.UserRepo, codeRepo domain.CodeRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req forgotReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_FIELDS", "message": "Некорректные данные"})
		}
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error_code": "INVALID_EMAIL", "message": "Некорректный формат email"})
		}
		u, err := userRepo.GetByEmail(req.Email)
		if err != nil || u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error_code": "NOT_FOUND", "message": "Пользователь не найден"})
		}

		ok, _ := codeRepo.ResendAllowed(u.ID, domain.CodeReset)
		if !ok {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error_code": "RATE_LIMIT_EXCEEDED", "message": "Слишком много запросов. Попробуйте позже"})
		}

		code, err := security.RandomDigits(6)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error_code": "SERVER_ERROR", "message": "Не удалось отправить код"})
		}
		if err := codeRepo.Save(domain.VerificationCode{
			UserID:    u.ID,
			Kind:      domain.CodeReset,
			Code:      code,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			SentTo:    u.Email,
		}); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error_code": "SERVER_ERROR", "message": "Не удалось отправить код"})
		}

		return c.JSON(fiber.Map{"message": "Код восстановления отправлен повторно"})
	}
}
