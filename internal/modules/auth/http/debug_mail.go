package http

import (
	"auth/internal/platform/notify"

	"github.com/gofiber/fiber/v2"
)

func DebugSendMailHandler(mailer *notify.Mailer) fiber.Handler {
	return func(c *fiber.Ctx) error {
		to := c.Query("to")
		if to == "" {
			to = "test@example.com"
		}
		if mailer == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "mailer is nil",
			})
		}
		if err := mailer.SendSignupCode(c.Context(), to, "123456"); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.JSON(fiber.Map{"ok": true})
	}
}
