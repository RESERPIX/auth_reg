package domain

import "time"

type Session struct {
	ID               string
	UserID           string
	RefreshTokenHash string
	DeviceName       *string
	IPAddress        *string
	UserAgent        *string
	LastActive       time.Time
	CreatedAt        time.Time
	RevokedAt        *time.Time

	ExpiresAt time.Time // <-- ДОБАВИЛИ
}

type SessionRepo interface {
	Create(s Session) (*Session, error)
	ListByUser(userID string, page, limit int) ([]Session, int, error)
	Revoke(sessionID, userID string) error
	RevokeOthers(currentSessionID, userID string) (int, error)
	RevokeCurrent(sessionID, userID string) error
	RevokeAll(userID string) (int, error)

	FindByRefreshHash(hash string) (*Session, error) // <-- ДОБАВИЛИ
}
