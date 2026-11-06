package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

const userCols = `id, login::text, display_name, password_hash, role, theme, is_active, must_change_password, created_at, updated_at, last_login_at`

func scanUser(r rowScanner) (domain.User, error) {
	var u domain.User
	err := r.Scan(&u.ID, &u.Login, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Theme,
		&u.IsActive, &u.MustChangePassword, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	return u, err
}

// CreateUser inserts u. A zero ID is generated; timestamps are set by the database.
func (s *Store) CreateUser(ctx context.Context, u *domain.User) error {
	u.ID = newID(u.ID)
	if u.Theme == "" {
		u.Theme = domain.ThemeLight
	}
	err := s.q.QueryRow(ctx, `
		INSERT INTO users (id, login, display_name, password_hash, role, theme, is_active, must_change_password, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at, updated_at`,
		u.ID, u.Login, u.DisplayName, u.PasswordHash, u.Role, u.Theme, u.IsActive, u.MustChangePassword, u.LastLoginAt,
	).Scan(&u.CreatedAt, &u.UpdatedAt)
	return mapErr("create user", err)
}

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return queryOne(ctx, s.q, "get user", scanUser,
		`SELECT `+userCols+` FROM users WHERE id = $1`, id)
}

func (s *Store) GetUserByLogin(ctx context.Context, login string) (*domain.User, error) {
	return queryOne(ctx, s.q, "get user by login", scanUser,
		`SELECT `+userCols+` FROM users WHERE login = $1`, login)
}

func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	return queryAll(ctx, s.q, "list users", scanUser,
		`SELECT `+userCols+` FROM users ORDER BY login`)
}

// UpdateUser overwrites all mutable user fields and refreshes updated_at.
func (s *Store) UpdateUser(ctx context.Context, u *domain.User) error {
	err := s.q.QueryRow(ctx, `
		UPDATE users
		SET login = $2, display_name = $3, password_hash = $4, role = $5, theme = $6,
		    is_active = $7, must_change_password = $8, last_login_at = $9, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`,
		u.ID, u.Login, u.DisplayName, u.PasswordHash, u.Role, u.Theme,
		u.IsActive, u.MustChangePassword, u.LastLoginAt,
	).Scan(&u.UpdatedAt)
	return mapErr("update user", err)
}

// DeleteUser removes the user; sessions and permissions cascade.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete user", `DELETE FROM users WHERE id = $1`, id)
}

func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.q.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE role = $1 AND is_active`, domain.RoleAdmin).Scan(&n)
	return n, mapErr("count active admins", err)
}

// Sessions

const sessionCols = `id, user_id, token_hash, created_at, expires_at, last_seen_at, ip, COALESCE(user_agent, '')`

func scanSession(r rowScanner) (domain.Session, error) {
	var x domain.Session
	err := r.Scan(&x.ID, &x.UserID, &x.TokenHash, &x.CreatedAt, &x.ExpiresAt,
		&x.LastSeenAt, &x.IP, &x.UserAgent)
	return x, err
}

// CreateSession inserts s. Zero CreatedAt/LastSeenAt default to now().
func (s *Store) CreateSession(ctx context.Context, x *domain.Session) error {
	x.ID = newID(x.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, ip, user_agent)
		VALUES ($1, $2, $3, COALESCE($4, now()), $5, COALESCE($6, now()), $7, $8)
		RETURNING created_at, last_seen_at`,
		x.ID, x.UserID, x.TokenHash, timeOrNil(x.CreatedAt), x.ExpiresAt,
		timeOrNil(x.LastSeenAt), x.IP, x.UserAgent,
	).Scan(&x.CreatedAt, &x.LastSeenAt)
	return mapErr("create session", err)
}

// GetSessionByTokenHash returns the session regardless of expiry; the service enforces limits.
func (s *Store) GetSessionByTokenHash(ctx context.Context, hash []byte) (*domain.Session, error) {
	return queryOne(ctx, s.q, "get session", scanSession,
		`SELECT `+sessionCols+` FROM sessions WHERE token_hash = $1`, hash)
}

// TouchSession records activity at the given time and moves expires_at to idleExtendTo.
func (s *Store) TouchSession(ctx context.Context, id uuid.UUID, at time.Time, idleExtendTo time.Time) error {
	return execOne(ctx, s.q, "touch session",
		`UPDATE sessions SET last_seen_at = $2, expires_at = $3 WHERE id = $1`,
		id, at, idleExtendTo)
}

func (s *Store) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return mapErr("delete session", err)
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return mapErr("delete user sessions", err)
}
