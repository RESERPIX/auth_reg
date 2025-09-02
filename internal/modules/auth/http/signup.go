package http

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"auth/internal/modules/auth/domain"
	"auth/internal/platform/notify"
	"auth/internal/platform/security"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type signUpReq struct {
	Email            string  `json:"email" validate:"required,email"`
	Password         string  `json:"password" validate:"required,min=8,max=50"`
	FirstName        string  `json:"first_name" validate:"required,min=2,max=50"`
	LastName         string  `json:"last_name" validate:"required,min=2,max=50"`
	Role             string  `json:"role" validate:"required,oneof=journalist guide restaurant"`
	Phone            *string `json:"phone" validate:"omitempty,e164"`
	PrivacyAgreement bool    `json:"privacy_agreement" validate:"eq=true"`
}

var validate = validator.New()

type signUpResp struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

func SignUpHandler(
	userRepo domain.UserRepo,
	codeRepo domain.CodeRepo,
	mailer *notify.Mailer,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req signUpReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Некорректные данные",
			})
		}

		// Валидация
		if err := validate.Struct(req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "VALIDATION_ERROR",
				"message":    "Ошибка валидации",
				// Опционально: можно добавить детали err
			})
		}

		// Дополнительно: строгая проверка email
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_EMAIL",
				"message":    "Некорректный формат email",
			})
		}

		// Проверка уникальности
		exists, err := userRepo.ExistsByEmail(strings.ToLower(req.Email))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось проверить email",
			})
		}
		if exists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error_code": "EMAIL_TAKEN",
				"message":    "Email уже занят",
			})
		}

		// Хеширование пароля
		pwHash, err := security.HashPassword(req.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось обработать пароль",
			})
		}

		// Создание пользователя
		u, err := userRepo.Create(domain.CreateUserParams{
			Email:        strings.ToLower(req.Email),
			Phone:        req.Phone,
			FirstName:    req.FirstName,
			LastName:     req.LastName,
			Role:         domain.Role(req.Role),
			PasswordHash: &pwHash,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось зарегистрировать пользователя",
			})
		}

		// Генерация кода подтверждения
		code, err := security.RandomDigits(6)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось сгенерировать код подтверждения",
			})
		}

		// Сохранение кода
		err = codeRepo.Save(domain.VerificationCode{
			UserID:    u.ID,
			Kind:      domain.CodeSignup,
			Code:      code,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			SentTo:    u.Email,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось сохранить код подтверждения",
			})
		}

		// Отправка письма с кодом
		if mailer != nil {
			if err := mailer.SendSignupCode(c.Context(), u.Email, code); err != nil {
				// залогируем и вернём 500, чтобы сразу увидеть проблему
				fmt.Printf("send mail error: %v\n", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error_code": "MAIL_SEND_ERROR",
					"message":    "Не удалось отправить письмо с кодом",
				})
			}
		}

		return c.Status(fiber.StatusCreated).JSON(signUpResp{
			Message: "Регистрация успешна. Подтвердите email",
			UserID:  u.ID,
		})
	}
}
