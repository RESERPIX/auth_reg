package http

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"auth/internal/modules/auth/domain"
)

type deviceDTO struct {
	ID         string  `json:"id"`
	DeviceName *string `json:"device_name"`
	LastActive string  `json:"last_active"`
	IPAddress  *string `json:"ip_address"`
	Location   *string `json:"location,omitempty"` // пока пусто
}

type devicesResp struct {
	Devices []deviceDTO `json:"devices"`
	Total   int         `json:"total"`
	Page    int         `json:"page"`
	Limit   int         `json:"limit"`
}

func ListDevicesHandler(sessions domain.SessionRepo) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uid, _ := c.Locals("user_id").(string)
		if uid == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}

		page, _ := strconv.Atoi(c.Query("page", "1"))
		limit, _ := strconv.Atoi(c.Query("limit", "10"))
		if page <= 0 {
			page = 1
		}
		if limit <= 0 || limit > 100 {
			limit = 10
		}

		items, total, err := sessions.ListByUser(uid, page, limit)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error_code": "SERVER_ERROR",
				"message":    "Не удалось загрузить данные",
			})
		}

		out := make([]deviceDTO, 0, len(items))
		for _, s := range items {
			last := s.LastActive
			if last.IsZero() {
				last = s.CreatedAt
			}
			out = append(out, deviceDTO{
				ID:         s.ID,
				DeviceName: s.DeviceName,
				LastActive: last.UTC().Format(time.RFC3339),
				IPAddress:  s.IPAddress,
				// Location — можно будет вычислять по IP позже
			})
		}

		return c.JSON(devicesResp{
			Devices: out,
			Total:   total,
			Page:    page,
			Limit:   limit,
		})
	}
}
