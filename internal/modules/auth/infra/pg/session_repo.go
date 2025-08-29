package pg

import (
	"context"

	"auth/internal/modules/auth/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepo struct{ db *pgxpool.Pool }

func NewSessionRepo(db *pgxpool.Pool) *SessionRepo { return &SessionRepo{db: db} }

func (r *SessionRepo) Create(s domain.Session) (*domain.Session, error) {
	ctx := context.Background()
	q := `INSERT INTO sessions (user_id, refresh_token_hash, device_name, ip_address, user_agent)
	      VALUES ($1, $2, $3, $4, $5)
	      RETURNING id, user_id, refresh_token_hash, device_name, ip_address, user_agent, last_active, created_at, revoked_at`
	row := r.db.QueryRow(ctx, q, s.UserID, s.RefreshTokenHash, s.DeviceName, s.IPAddress, s.UserAgent)
	var out domain.Session
	if err := row.Scan(&out.ID, &out.UserID, &out.RefreshTokenHash, &out.DeviceName, &out.IPAddress, &out.UserAgent, &out.LastActive, &out.CreatedAt, &out.RevokedAt); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *SessionRepo) ListByUser(userID string, page, limit int) ([]domain.Session, int, error) {
	ctx := context.Background()
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1`, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * limit
	rows, err := r.db.Query(ctx, `SELECT id, user_id, refresh_token_hash, device_name, ip_address, user_agent, last_active, created_at, revoked_at
	                               FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []domain.Session{}
	for rows.Next() {
		var s domain.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.RefreshTokenHash, &s.DeviceName, &s.IPAddress, &s.UserAgent, &s.LastActive, &s.CreatedAt, &s.RevokedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, nil
}

func (r *SessionRepo) Revoke(sessionID, userID string) error {
	_, err := r.db.Exec(context.Background(),
		`UPDATE sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, sessionID, userID)
	return err
}

func (r *SessionRepo) RevokeOthers(currentSessionID, userID string) (int, error) {
	ct, err := r.db.Exec(context.Background(),
		`UPDATE sessions SET revoked_at=now()
		 WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL`, userID, currentSessionID)
	return int(ct.RowsAffected()), err
}

func (r *SessionRepo) RevokeCurrent(sessionID, userID string) error {
	return r.Revoke(sessionID, userID)
}

func (r *SessionRepo) RevokeAll(userID string) (int, error) {
	ct, err := r.db.Exec(context.Background(),
		`UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return int(ct.RowsAffected()), err
}

func (r *SessionRepo) FindByRefreshHash(hash string) (*domain.Session, error) {
	row := r.db.QueryRow(context.Background(),
		`SELECT id, user_id, refresh_token_hash, device_name, ip_address, user_agent,
		        last_active, created_at, revoked_at, expires_at
		   FROM sessions WHERE refresh_token_hash=$1`, hash)
	var s domain.Session
	if err := row.Scan(&s.ID, &s.UserID, &s.RefreshTokenHash, &s.DeviceName,
		&s.IPAddress, &s.UserAgent, &s.LastActive, &s.CreatedAt, &s.RevokedAt, &s.ExpiresAt); err != nil {
		return nil, err
	}
	return &s, nil
}
