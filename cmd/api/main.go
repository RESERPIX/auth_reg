package main

import (
	"log"

	"auth/internal/db"
	"auth/internal/platform/config"
	phttp "auth/internal/platform/http"
	"auth/internal/platform/notify"

	authhttp "auth/internal/modules/auth/http"
)

func main() {
	cfg := config.Load()

	dbpool := db.MustOpen(cfg.PGDSN)
	defer dbpool.Close()

	mailer := notify.NewMailer(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)
	authModule := authhttp.NewModulePG(dbpool, cfg.JWTSecret, cfg.AccessTTL).WithMailer(mailer)
	app := phttp.NewServer(phttp.Options{AppName: "news-auth"}, authModule)

	log.Printf("listening on %s", cfg.HTTPAddr)
	if err := app.Listen(cfg.HTTPAddr); err != nil {
		log.Fatal(err)
	}
}
