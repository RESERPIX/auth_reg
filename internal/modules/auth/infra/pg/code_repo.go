// internal/modules/auth/infra/pg/code_repo.go
package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"auth/internal/modules/auth/domain"
)

var (
	// такие же семантики, как в in-memory реализации
	ErrCodeInvalid = errors.New("code_invalid")
	ErrCodeExpired = errors.New("code_expired")
)

type CodeRepo struct {
	db       *pgxpool.Pool
	cooldown time.Duration
}

func NewCodeRepo(db *pgxpool.Pool) *CodeRepo {
	return &CodeRepo{db: db, cooldown: 60 * time.Second}
}

func (r *CodeRepo) Save(c domain.VerificationCode) error {
	_, err := r.db.Exec(context.Background(),
		`INSERT INTO verification_codes (user_id, kind, code, expires_at, sent_to)
		 VALUES ($1, $2, $3, $4, $5)`,
		c.UserID, c.Kind, c.Code, c.ExpiresAt, c.SentTo,
	)
	return err
}

func (r *CodeRepo) Consume(userID string, kind domain.CodeKind, code string) (*domain.VerificationCode, error) {
	ctx := context.Background()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var v domain.VerificationCode
	// блокируем последнюю запись с таким кодом
	row := tx.QueryRow(ctx, `
SELECT id, user_id, kind, code, expires_at, consumed_at, sent_to, created_at
FROM verification_codes
WHERE user_id=$1 AND kind=$2 AND code=$3
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE
`, userID, kind, code)

	if err := row.Scan(&v.ID, &v.UserID, &v.Kind, &v.Code, &v.ExpiresAt, &v.ConsumedAt, &v.SentTo, &v.CreatedAt); err != nil {
		// нет такого кода
		return nil, ErrCodeInvalid
	}

	now := time.Now().UTC()
	if v.ConsumedAt != nil {
		return nil, ErrCodeInvalid
	}
	if now.After(v.ExpiresAt) {
		return nil, ErrCodeExpired
	}

	if _, err := tx.Exec(ctx, `UPDATE verification_codes SET consumed_at=$2 WHERE id=$1`, v.ID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	v.ConsumedAt = &now
	return &v, nil
}

func (r *CodeRepo) ResendAllowed(userID string, kind domain.CodeKind) (bool, error) {
	var last time.Time
	err := r.db.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(created_at), 'epoch') FROM verification_codes WHERE user_id=$1 AND kind=$2`,
		userID, kind,
	).Scan(&last)
	if err != nil {
		return false, err
	}
	return time.Since(last) >= r.cooldown, nil
}
