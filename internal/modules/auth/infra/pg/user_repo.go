package pg

import (
	"context"
	"strings"
	"time"

	"auth/internal/modules/auth/domain"

	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct{ db *pgxpool.Pool }

func NewUserRepo(db *pgxpool.Pool) *UserRepo { return &UserRepo{db: db} }

func scanUser(row interface {
	Scan(dest ...any) error
}) (*domain.User, error) {
	var u domain.User
	var phone *string
	var pw *string
	var created, updated time.Time
	if err := row.Scan(&u.ID, &u.Email, &phone, &u.FirstName, &u.LastName, &u.Role,
		&pw, &u.EmailConfirmed, &u.PhoneConfirmed, &u.IsBlocked, &created, &updated); err != nil {
		return nil, err
	}
	u.Phone = phone
	u.PasswordHash = pw
	u.CreatedAt = created
	u.UpdatedAt = updated
	return &u, nil
}

func (r *UserRepo) Create(p domain.CreateUserParams) (*domain.User, error) {
	ctx := context.Background()
	q := `
INSERT INTO users (email, phone, first_name, last_name, role, password_hash)
VALUES (LOWER($1), $2, $3, $4, $5, $6)
RETURNING id, email, phone, first_name, last_name, role, password_hash,
          email_confirmed, phone_confirmed, is_blocked, created_at, updated_at`
	row := r.db.QueryRow(ctx, q, p.Email, p.Phone, p.FirstName, p.LastName, p.Role, p.PasswordHash)
	return scanUser(row)
}

func (r *UserRepo) GetByEmail(email string) (*domain.User, error) {
	ctx := context.Background()
	q := `SELECT id, email, phone, first_name, last_name, role, password_hash,
	             email_confirmed, phone_confirmed, is_blocked, created_at, updated_at
	      FROM users WHERE email = LOWER($1)`
	row := r.db.QueryRow(ctx, q, strings.ToLower(email))
	return scanUser(row)
}

func (r *UserRepo) ExistsByEmail(email string) (bool, error) {
	ctx := context.Background()
	var ok bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=LOWER($1))`, email).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func (r *UserRepo) ConfirmEmail(userID string) error {
	_, err := r.db.Exec(context.Background(), `UPDATE users SET email_confirmed=true, updated_at=now() WHERE id=$1`, userID)
	return err
}

func (r *UserRepo) GetByID(id string) (*domain.User, error) {
	row := r.db.QueryRow(context.Background(), `SELECT id, email, phone, first_name, last_name, role, password_hash,
	 email_confirmed, phone_confirmed, is_blocked, created_at, updated_at FROM users WHERE id=$1`, id)
	return scanUser(row)
}

func (r *UserRepo) UpdateProfile(userID string, firstName, lastName, phone *string) error {
	ctx := context.Background()
	q := `UPDATE users SET
	        first_name = COALESCE($2, first_name),
	        last_name  = COALESCE($3, last_name),
	        phone      = COALESCE($4, phone),
	        updated_at = now()
	      WHERE id=$1`
	_, err := r.db.Exec(ctx, q, userID, firstName, lastName, phone)
	return err
}

func (r *UserRepo) UpdatePassword(userID string, newHash string) error {
	_, err := r.db.Exec(context.Background(), `UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1`, userID, newHash)
	return err
}

func (r *UserRepo) Delete(id string) error {
	_, err := r.db.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id)
	return err
}
