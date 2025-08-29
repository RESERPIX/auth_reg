package http

import (
	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
)

func DeleteDeviceHandler(sessions domain.SessionRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}

		deviceID := c.Params("device_id")
		if deviceID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error_code": "INVALID_FIELDS",
				"message":    "Нужно указать device_id",
			})
		}

		if err := sessions.Revoke(deviceID, uid); err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error_code": "NOT_FOUND",
				"message":    "Сессия не найдена",
			})
		}

		return c.JSON(fiber.Map{"message": "Сессия успешно завершена"})
	}
}
func DeleteOtherDevicesHandler(sessions domain.SessionRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		sid, _ := c.Locals("session_id").(string)
		if uid == "" || sid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED", "message": "Требуется авторизация",
			})
		}
		count, _ := sessions.RevokeOthers(sid, uid)
		return c.JSON(fiber.Map{
			"message":             "Все остальные сессии завершены",
			"sessions_terminated": count,
		})
	}
}

func DeleteCurrentSessionHandler(sessions domain.SessionRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		sid, _ := c.Locals("session_id").(string)
		if uid == "" || sid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED", "message": "Требуется авторизация",
			})
		}
		if err := sessions.RevokeCurrent(sid, uid); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR", "message": "Не удалось завершить сессию",
			})
		}
		return c.JSON(fiber.Map{"message": "Сессия успешно завершена"})
	}
}
