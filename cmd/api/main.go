package main

import (
	"fmt"
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
	// for production ensure this is false; can be enabled for local dev via SMTP_INSECURE_SKIP_VERIFY
	mailer.InsecureSkipVerify = cfg.SMTPInsecureSkipVerify
	fmt.Printf("SMTP: host=%s port=%d from=%s insecure_skip_verify=%v\n", cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPFrom, mailer.InsecureSkipVerify)
	authModule := authhttp.NewModulePG(dbpool, cfg.JWTSecret, cfg.AccessTTL).WithMailer(mailer)
	app := phttp.NewServer(phttp.Options{AppName: "news-auth"}, authModule)

	log.Printf("listening on %s", cfg.HTTPAddr)
	if err := app.Listen(cfg.HTTPAddr); err != nil {
		log.Fatal(err)
	}
}
