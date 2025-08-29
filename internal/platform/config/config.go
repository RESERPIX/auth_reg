package config

import (
	"os"
	"time"
)

type Config struct {
	HTTPAddr  string
	Env       string
	PGDSN     string
	JWTSecret string
	AccessTTL time.Duration

	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string
}

func Load() Config {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	dsn := os.Getenv("PG_DSN")
	if dsn == "" {
		dsn = "postgres://yakavkaz_user:45399849tT.@localhost:5432/yakavkaz_auth?sslmode=disable"
	}
	return Config{
		HTTPAddr:  addr,
		Env:       os.Getenv("APP_ENV"),
		PGDSN:     dsn,
		JWTSecret: getenv("JWT_SECRET", "super-secret"),
		AccessTTL: 15 * time.Minute,

		SMTPHost: getenv("SMTP_HOST", "mailhog"),
		SMTPPort: 5432,
		SMTPUser: os.Getenv("SMTP_USER"),
		SMTPPass: os.Getenv("SMTP_PASS"),
		SMTPFrom: getenv("SMTP_FROM", "no-reply@example.com"),
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
