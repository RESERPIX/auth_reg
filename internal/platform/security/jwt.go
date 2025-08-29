package security

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secret    []byte
	accessTTL time.Duration
}

func NewJWTManager(secret string, accessTTL time.Duration) *JWTManager {
	return &JWTManager{secret: []byte(secret), accessTTL: accessTTL}
}

func (j *JWTManager) IssueAccess(userID, role, sessionID string) (string, time.Time, error) {
	exp := time.Now().Add(j.accessTTL)
	claims := jwt.MapClaims{
		"sub":  userID,
        "role": role,
        "sid":  sessionID,        // ← добавили sid
		"exp":  exp.Unix(),
		"iat":  time.Now().Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := t.SignedString(j.secret)
	return token, exp, err
}


// refresh пока делаем простым random-стрингом
func IssueRefresh() (string, string, error) {
	token, err := RandomDigits(30) // простой вариант, потом заменим на crypto/rand
	if err != nil {
		return "", "", err
	}
	return token, token, nil
}
