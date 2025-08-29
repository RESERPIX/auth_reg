package domain

import "time"

type CodeKind string

const (
	CodeSignup CodeKind = "signup"
	CodeTwoFA  CodeKind = "twofa"
	CodeReset  CodeKind = "reset"
)

type VerificationCode struct {
	ID         string
	UserID     string
	Kind       CodeKind
	Code       string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	SentTo     string
	CreatedAt  time.Time
}

type CodeRepo interface {
	Save(c VerificationCode) error
	Consume(userID string, kind CodeKind, code string) (*VerificationCode, error)
	ResendAllowed(userID string, kind CodeKind) (bool, error)
}
