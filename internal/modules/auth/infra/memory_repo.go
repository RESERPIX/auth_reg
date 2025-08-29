package infra

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"auth/internal/modules/auth/domain"
)

var (
	ErrCodeInvalid = errors.New("code_invalid")
	ErrCodeExpired = errors.New("code_expired")
)

type memUserRepo struct {
	mu      sync.RWMutex
	users   map[string]*domain.User // id -> user
	byEmail map[string]string       // email -> id
}

func NewMemUserRepo() domain.UserRepo {
	return &memUserRepo{
		users:   make(map[string]*domain.User),
		byEmail: make(map[string]string),
	}
}

func (r *memUserRepo) Create(p domain.CreateUserParams) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byEmail[p.Email]; ok {
		return nil, errors.New("email_taken")
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	u := &domain.User{
		ID: id, Email: p.Email, Phone: p.Phone, FirstName: p.FirstName, LastName: p.LastName,
		Role: p.Role, PasswordHash: p.PasswordHash, CreatedAt: now, UpdatedAt: now,
	}
	r.users[id] = u
	r.byEmail[p.Email] = id
	return u, nil
}

// ДОБАВЬ:
// ДОБАВЬ:
func (r *memUserRepo) GetByID(id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	if !ok {
		return nil, errors.New("not_found")
	}
	return u, nil
}

func (r *memUserRepo) UpdateProfile(userID string, firstName *string, lastName *string, phone *string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return errors.New("not_found")
	}
	if firstName != nil {
		u.FirstName = strings.TrimSpace(*firstName)
	}
	if lastName != nil {
		u.LastName = strings.TrimSpace(*lastName)
	}
	if phone != nil {
		u.Phone = phone
	}
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memUserRepo) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok {
		return errors.New("not_found")
	}
	delete(r.users, id)
	// убрать из byEmail
	for e, uid := range r.byEmail {
		if uid == u.ID {
			delete(r.byEmail, e)
			break
		}
	}
	return nil
}

func (r *memUserRepo) GetByEmail(email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byEmail[email]
	if !ok {
		return nil, errors.New("not_found")
	}
	return r.users[id], nil
}

func (r *memUserRepo) ExistsByEmail(email string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.byEmail[email]
	return ok, nil
}

func (r *memUserRepo) ConfirmEmail(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return errors.New("not_found")
	}
	u.EmailConfirmed = true
	u.UpdatedAt = time.Now().UTC()
	return nil
}

type memSessionRepo struct {
	mu       sync.RWMutex
	sessions map[string]*domain.Session
	byUser   map[string][]string
}

func NewMemSessionRepo() domain.SessionRepo {
	return &memSessionRepo{
		sessions: make(map[string]*domain.Session),
		byUser:   make(map[string][]string),
	}
}

func (r *memSessionRepo) Create(s domain.Session) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	s.CreatedAt = now
	s.LastActive = now
	if s.ExpiresAt.IsZero() { // <-- ДОБАВИЛИ
		s.ExpiresAt = now.Add(30 * 24 * time.Hour)
	}
	cp := s
	r.sessions[s.ID] = &cp
	r.byUser[s.UserID] = append(r.byUser[s.UserID], s.ID)
	return &cp, nil
}

func (r *memSessionRepo) FindByRefreshHash(hash string) (*domain.Session, error) { // <-- НОВОЕ
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.sessions {
		if s.RefreshTokenHash == hash {
			cp := *s
			return &cp, nil
		}
	}
	return nil, errors.New("not_found")
}

func (r *memSessionRepo) ListByUser(userID string, page, limit int) ([]domain.Session, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byUser[userID]
	total := len(ids)
	if total == 0 {
		return []domain.Session{}, 0, nil
	}
	start := (page - 1) * limit
	if start >= total {
		return []domain.Session{}, total, nil
	}
	end := start + limit
	if end > total {
		end = total
	}
	out := make([]domain.Session, 0, end-start)
	for _, id := range ids[start:end] {
		s := r.sessions[id]
		out = append(out, *s)
	}
	return out, total, nil
}

func (r *memSessionRepo) Revoke(sessionID, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[sessionID]
	if !ok || s.UserID != userID {
		return errors.New("not_found")
	}
	now := time.Now().UTC()
	s.RevokedAt = &now
	return nil
}

func (r *memSessionRepo) RevokeOthers(currentSessionID, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := r.byUser[userID]
	count := 0
	now := time.Now().UTC()
	for _, id := range ids {
		if id == currentSessionID {
			continue
		}
		if s, ok := r.sessions[id]; ok {
			if s.RevokedAt == nil {
				s.RevokedAt = &now
				count++
			}
		}
	}
	return count, nil
}

func (r *memSessionRepo) RevokeCurrent(sessionID, userID string) error {
	return r.Revoke(sessionID, userID)
}

type memCodeRepo struct {
	mu       sync.RWMutex
	codes    []domain.VerificationCode
	lastSent map[string]time.Time // key: userID+"|"+kind
	cooldown time.Duration
}

func (r *memSessionRepo) RevokeAll(userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := r.byUser[userID]
	count := 0
	now := time.Now().UTC()
	for _, id := range ids {
		if s, ok := r.sessions[id]; ok && s.RevokedAt == nil {
			s.RevokedAt = &now
			count++
		}
	}
	return count, nil
}

func NewMemCodeRepo() domain.CodeRepo {
	return &memCodeRepo{
		codes:    []domain.VerificationCode{},
		lastSent: map[string]time.Time{},
		cooldown: 60 * time.Second, // простой лимит
	}
}

func (r *memCodeRepo) Save(c domain.VerificationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	r.codes = append(r.codes, c)
	key := c.UserID + "|" + string(c.Kind)
	r.lastSent[key] = time.Now().UTC()
	return nil
}

func (r *memCodeRepo) Consume(userID string, kind domain.CodeKind, code string) (*domain.VerificationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	var foundSame bool

	for i := range r.codes {
		c := &r.codes[i]
		if c.UserID == userID && c.Kind == kind && c.ConsumedAt == nil {
			if c.Code == code {
				foundSame = true
				if c.ExpiresAt.Before(now) {
					return nil, ErrCodeExpired
				}
				c.ConsumedAt = &now
				cp := *c
				return &cp, nil
			}
		}
	}
	if foundSame {
		// если код совпал, но истёк — мы бы уже вернули ErrCodeExpired
	}
	return nil, ErrCodeInvalid
}

func (r *memCodeRepo) ResendAllowed(userID string, kind domain.CodeKind) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := userID + "|" + string(kind)
	last, ok := r.lastSent[key]
	if !ok {
		return true, nil
	}
	return time.Since(last) >= r.cooldown, nil
}

func (r *memUserRepo) UpdatePassword(userID string, newHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return errors.New("not_found")
	}
	u.PasswordHash = &newHash
	u.UpdatedAt = time.Now().UTC()
	return nil
}
