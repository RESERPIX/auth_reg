package security

import (
	"errors"
	"fmt"
)

// VerifyOAuthToken имитирует проверку у стороннего сервиса.
// В реальном проекте нужно дергать API Google/Yandex.
func VerifyOAuthToken(provider, token string) (string, error) {
	if token == "" {
		return "", errors.New("invalid_token")
	}
	// Заглушка: email формируется из токена
	email := fmt.Sprintf("%s_user_%s@example.com", provider, token[:6])
	return email, nil
}
