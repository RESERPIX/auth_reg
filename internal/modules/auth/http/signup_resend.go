package http

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/notify"
	"auth/internal/platform/security"
)

type resendReq struct {
	Email string `json:"email"`
}

type resendResp struct {
	Message string `json:"message"`
}

func SignUpResendHandler(
	userRepo domain.UserRepo,
	codeRepo domain.CodeRepo,
	mailer *notify.Mailer, // <<< добавили
) fiber.Handler {
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

		u, err := userRepo.GetByEmail(req.Email)
		if err != nil {
			// differentiate DB/internal error from not-found
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось получить пользователя",
			})
		}
		if u == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error_code": "NOT_FOUND",
				"message":    "Пользователь не найден",
			})
		}
		if u.EmailConfirmed {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "ALREADY_CONFIRMED",
				"message":    "Email уже подтверждён",
			})
		}

		ok, err := codeRepo.ResendAllowed(u.ID, domain.CodeSignup)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось проверить лимит отправки",
			})
		}
		if !ok {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error_code": "RATE_LIMIT_EXCEEDED",
				"message":    "Слишком много запросов. Попробуйте позже",
			})
		}

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
				"message":    "Не удалось сохранить код",
			})
		}

		// 🔔 Отправка письма
		if mailer != nil {
			if err := mailer.SendSignupCode(c.Context(), u.Email, code); err != nil {
				fmt.Printf("send mail error (resend): %v\n", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error_code": "MAIL_SEND_ERROR",
					"message":    "Не удалось отправить письмо с кодом",
				})
			}
		}

		return c.JSON(resendResp{Message: "Код подтверждения отправлен повторно"})
	}
}
