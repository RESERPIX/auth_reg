package config

import (
	"os"
	"strconv"
	"strings"
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
	// If true, skip TLS cert verification when connecting to SMTP (for local dev only).
	SMTPInsecureSkipVerify bool
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() Config {
	// HTTP
	addr := getenv("HTTP_ADDR", ":8080")

	// ⬅️ ВАЖНО: дефолтный SMTP порт — 1025 (а не 5432)
	smtpPort := 1025
	if v := os.Getenv("SMTP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			smtpPort = p
		}
	}

	smtpInsecure := false
	if v := os.Getenv("SMTP_INSECURE_SKIP_VERIFY"); v != "" {
		lv := strings.ToLower(strings.TrimSpace(v))
		if lv == "1" || lv == "true" || lv == "yes" {
			smtpInsecure = true
		}
	}

	return Config{
		HTTPAddr:  addr,
		Env:       os.Getenv("APP_ENV"),
		PGDSN:     getenv("PG_DSN", "postgres://news_user:news_pass@postgres:5432/news_auth?sslmode=disable"),
		JWTSecret: getenv("JWT_SECRET", "super-secret"),
		AccessTTL: 15 * time.Minute,

		SMTPHost:               getenv("SMTP_HOST", "mailhog"),
		SMTPPort:               smtpPort,
		SMTPUser:               os.Getenv("SMTP_USER"),
		SMTPPass:               os.Getenv("SMTP_PASS"),
		SMTPFrom:               getenv("SMTP_FROM", "no-reply@news.local"),
		SMTPInsecureSkipVerify: smtpInsecure,
	}
}
