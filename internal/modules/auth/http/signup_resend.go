package http

import (
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/security"
)

type resendReq struct {
	Email string `json:"email"`
}

type resendResp struct {
	Message string `json:"message"`
}

func SignUpResendHandler(userRepo domain.UserRepo, codeRepo domain.CodeRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req resendReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
		if req.Email == "" || func() bool { _, e := mail.ParseAddress(req.Email); return e != nil }() {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_EMAIL",
				"message":    "Некорректный формат email",
			})
		}

		// Пользователь должен существовать
		u, err := userRepo.GetByEmail(req.Email)
		if err != nil || u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error_code": "NOT_FOUND",
				"message":    "Пользователь не найден",
			})
		}

		// Если уже подтверждён — повторная отправка не нужна
		if u.EmailConfirmed {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "ALREADY_CONFIRMED",
				"message":    "Email уже подтверждён",
			})
		}

		// Антиспам-лимит
		ok, _ := codeRepo.ResendAllowed(u.ID, domain.CodeSignup)
		if !ok {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error_code": "RATE_LIMIT_EXCEEDED",
				"message":    "Слишком много запросов. Попробуйте позже",
			})
		}

		// Генерируем новый код и сохраняем
		code, err := security.RandomDigits(6)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось сгенерировать код",
			})
		}
		if err := codeRepo.Save(domain.VerificationCode{
			UserID:    u.ID,
			Kind:      domain.CodeSignup,
			Code:      code,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			SentTo:    u.Email,
		}); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось отправить код",
			})
		}

		// TODO: интеграция с email-отправкой

		return c.JSON(resendResp{
			Message: "Код подтверждения отправлен повторно",
		})
	}
}
