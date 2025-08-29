package http

import (
	"net/mail"
	"strings"
	"time"

	"auth/internal/modules/auth/domain"
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

func SignUpHandler(userRepo domain.UserRepo, codeRepo domain.CodeRepo) fiber.Handler {
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
				"message":    err.Error(),
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
		exists, _ := userRepo.ExistsByEmail(strings.ToLower(req.Email))
		if exists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error_code": "EMAIL_TAKEN",
				"message":    "Email уже занят",
			})
		}

		// Хеш пароля (пока заглушка: просто сохраняем в поле)
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
				"message":    "Не удалось зарегистрироваться",
			})
		}

		// Сохраняем код подтверждения (пока просто в памяти)
		code, err := security.RandomDigits(6)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось сгенерировать код подтверждения",
			})
		} // TODO: генерация
		_ = codeRepo.Save(domain.VerificationCode{
			UserID:    u.ID,
			Kind:      domain.CodeSignup,
			Code:      code,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			SentTo:    u.Email,
		})

		return c.Status(fiber.StatusCreated).JSON(signUpResp{
			Message: "Регистрация успешна. Подтвердите email",
			UserID:  u.ID,
		})
	}
}
