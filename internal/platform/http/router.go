package http

import "github.com/gofiber/fiber/v2"

type Module interface {
	Register(r fiber.Router) // каждый модуль регистрирует свои маршруты на префиксе
}
