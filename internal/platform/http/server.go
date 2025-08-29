package http

import (
	"github.com/gofiber/fiber/v2"
)

type Options struct {
	AppName string
}

func NewServer(opts Options, modules ...Module) *fiber.App {
	app := fiber.New(fiber.Config{AppName: opts.AppName})

	// глобальные middleware можно добавить здесь (recover, compress, requestID и т.п.)

	api := app.Group("/api")
	v1 := api.Group("/v1")

	// регистрация модулей
	for _, m := range modules {
		m.Register(v1)
	}

	// health
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	return app
}
