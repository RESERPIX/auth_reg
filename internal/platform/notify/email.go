package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Mailer struct {
	host string
	port int
	user string
	pass string
	from string
	// If true, skip TLS certificate verification (useful for local dev like MailHog).
	InsecureSkipVerify bool
}

func NewMailer(host string, port int, user, pass, from string) *Mailer {
	return &Mailer{host: host, port: port, user: user, pass: pass, from: from, InsecureSkipVerify: false}
}

// send — простая отправка HTML-письма через net/smtp.
// Работает с MailHog (без аутентификации) и обычными серверами (PlainAuth).
func (m *Mailer) send(ctx context.Context, to, subject, htmlBody string) error {
	// MIME
	headers := map[string]string{
		"From":         m.from,
		"To":           to,
		"Subject":      encodeRFC2047(subject),
		"MIME-Version": "1.0",
		"Content-Type": "text/html; charset=UTF-8",
	}
	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(k + ": " + v + "\r\n")
	}
	sb.WriteString("\r\n")
	sb.WriteString(htmlBody)

	// AUTH (если задан логин)
	var auth smtp.Auth
	if m.user != "" {
		auth = smtp.PlainAuth("", m.user, m.pass, m.host)
	}

	// Dial
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}
	addr := net.JoinHostPort(m.host, strconv.Itoa(m.port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	// Close SMTP client on return; log Quit error if any.
	defer func() {
		if err := c.Quit(); err != nil {
			fmt.Printf("smtp client quit error: %v\n", err)
		}
	}()

	// 🔹 ЯВНО отправляем EHLO (hostname можно любой локальный)
	if err := c.Hello("localhost"); err != nil {
		return err
	}

	// 🔹 STARTTLS, если сервер умеет (MailHog умеет, но не требует)
	if ok, _ := c.Extension("STARTTLS"); ok {
		cfg := &tls.Config{
			ServerName:         m.host,
			InsecureSkipVerify: m.InsecureSkipVerify, // configurable
		}
		if err := c.StartTLS(cfg); err != nil {
			return err
		}
		// после TLS — повторим EHLO для обновления расширений
		if err := c.Hello("localhost"); err != nil {
			return err
		}
	}

	// 🔹 AUTH, если есть креды и сервер поддерживает
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
	}

	if err := c.Mail(m.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(sb.String())); err != nil {
		return err
	}
	return w.Close()
}

func (m *Mailer) SendSignupCode(ctx context.Context, to, code string) error {
	body := fmt.Sprintf(`<h2>Подтверждение e-mail</h2><p>Ваш код: <b>%s</b></p><p>Код действителен 1 час.</p>`, code)
	return m.send(ctx, to, "Подтверждение e-mail", body)
}

func (m *Mailer) SendResetCode(ctx context.Context, to, code string) error {
	body := fmt.Sprintf(`<h2>Сброс пароля</h2><p>Ваш код: <b>%s</b></p><p>Код действителен 1 час.</p>`, code)
	return m.send(ctx, to, "Сброс пароля", body)
}

// кодировка Subject в RFC2047 (на случай кириллицы)
func encodeRFC2047(s string) string {
	// простая форма Q-encoding
	return fmt.Sprintf("=?UTF-8?Q?%s?=", qEncode(s))
}

// минимальный Q-encode (без зависимостей)
func qEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' {
			if c == ' ' {
				b.WriteByte('_')
			} else {
				b.WriteByte(c)
			}
		} else {
			b.WriteString(fmt.Sprintf("=%02X", c))
		}
	}
	return b.String()
}

func (m *Mailer) Send2FACode(ctx context.Context, to, code string) error {
	body := fmt.Sprintf(
		`<h2>Вход в аккаунт</h2><p>Ваш 2FA-код: <b>%s</b></p><p>Код действителен 10 минут.</p>`, code)
	return m.send(ctx, to, "Код подтверждения входа (2FA)", body)
}
