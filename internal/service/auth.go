package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/auth"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// DefaultBootstrapLogin is used when EnsureBootstrapAdmin is called with an empty login.
const DefaultBootstrapLogin = "admin"

var loginRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{3,64}$`)

// sessionTouchInterval limits how often last_seen_at/expires_at are written.
const sessionTouchInterval = time.Minute

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// burnPasswordCheck spends roughly the cost of a real verification so that
// unknown logins are not distinguishable by timing.
func burnPasswordCheck(password string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = auth.HashPassword("tlsherd-timing-equalizer")
	})
	if dummyHash != "" {
		_, _ = auth.VerifyPassword(dummyHash, password)
	}
}

// LoginResult is returned by Login.
type LoginResult struct {
	Token     string // plaintext session token; shown once
	User      *domain.User
	Session   *domain.Session
	ExpiresAt time.Time
}

// Login verifies credentials and opens a session. Unknown user, wrong
// password and inactive user all yield domain.ErrUnauthorized.
func (s *Services) Login(ctx context.Context, login, password string, ip netip.Addr, userAgent string) (*LoginResult, error) {
	login = normalizeText(login)
	ipStr := ipString(ip)
	u, err := s.Store.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			burnPasswordCheck(password)
			s.recordLoginFailure(ctx, login, ipStr, "unknown_user")
			return nil, domain.ErrUnauthorized
		}
		return nil, fmt.Errorf("login: %w", err)
	}
	ok, verr := auth.VerifyPassword(u.PasswordHash, password)
	if verr != nil || !ok {
		s.recordLoginFailure(ctx, login, ipStr, "bad_password")
		return nil, domain.ErrUnauthorized
	}
	if !u.IsActive {
		s.recordLoginFailure(ctx, login, ipStr, "inactive")
		return nil, domain.ErrUnauthorized
	}

	token, hash, err := auth.NewSessionToken()
	if err != nil {
		return nil, fmt.Errorf("login: new token: %w", err)
	}
	now := s.now()
	sess := &domain.Session{
		UserID:     u.ID,
		TokenHash:  hash,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(SessionIdleTimeout),
		UserAgent:  truncate(userAgent, 256),
	}
	if ip.IsValid() {
		sess.IP = &ip
	}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.CreateSession(ctx, sess); err != nil {
			return err
		}
		u.LastLoginAt = &now
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		return s.audit(ctx, tx, u, "auth.login", "user", u.ID.String(), map[string]any{"ip": ipStr})
	})
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	s.log().Info("user logged in", "component", "service", "operation", "login",
		"user_id", u.ID, "login", u.Login, "ip", ipStr)
	return &LoginResult{Token: token, User: u, Session: sess, ExpiresAt: sess.ExpiresAt}, nil
}

// recordLoginFailure writes an audit row (no actor) and a warn log. Failures are
// expected under brute-force; keep messages free of password material.
func (s *Services) recordLoginFailure(ctx context.Context, login, ip, reason string) {
	s.log().Warn("login failed", "component", "service", "operation", "login",
		"login", login, "ip", ip, "reason", reason)
	if err := s.audit(ctx, s.Store, nil, "auth.login_failed", "user", login, map[string]any{
		"ip": ip, "reason": reason,
	}); err != nil {
		s.log().Error("audit login failure", "component", "service", "operation", "login", "error", err)
	}
}

// Logout closes the session identified by token. Unknown tokens are ignored.
func (s *Services) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	sess, err := s.Store.GetSessionByTokenHash(ctx, auth.HashToken(token))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("logout: %w", err)
	}
	if err := s.Store.DeleteSession(ctx, sess.ID); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	return nil
}

// LookupSession resolves a session token to its user. It enforces the idle
// and absolute limits, slides the idle window, and rejects inactive users.
func (s *Services) LookupSession(ctx context.Context, token string) (*domain.User, *domain.Session, error) {
	if token == "" {
		return nil, nil, domain.ErrUnauthorized
	}
	sess, err := s.Store.GetSessionByTokenHash(ctx, auth.HashToken(token))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil, domain.ErrUnauthorized
		}
		return nil, nil, fmt.Errorf("lookup session: %w", err)
	}
	now := s.now()
	absolute := sess.CreatedAt.Add(SessionMaxLifetime)
	if !sess.ExpiresAt.After(now) || !absolute.After(now) {
		_ = s.Store.DeleteSession(ctx, sess.ID)
		return nil, nil, domain.ErrUnauthorized
	}
	u, err := s.Store.GetUser(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil, domain.ErrUnauthorized
		}
		return nil, nil, fmt.Errorf("lookup session: %w", err)
	}
	if !u.IsActive {
		_ = s.Store.DeleteSession(ctx, sess.ID)
		return nil, nil, domain.ErrUnauthorized
	}
	if now.Sub(sess.LastSeenAt) >= sessionTouchInterval {
		extend := now.Add(SessionIdleTimeout)
		if extend.After(absolute) {
			extend = absolute
		}
		if err := s.Store.TouchSession(ctx, sess.ID, now, extend); err == nil {
			sess.LastSeenAt, sess.ExpiresAt = now, extend
		}
	}
	return u, sess, nil
}

// ChangeOwnPassword sets a new password for the actor and revokes all sessions.
// When must_change_password is set (bootstrap), oldPassword is not required;
// otherwise the current password must be verified. Clears must_change_password.
func (s *Services) ChangeOwnPassword(ctx context.Context, actor *domain.User, oldPassword, newPassword string) error {
	u, err := s.Store.GetUser(ctx, actor.ID)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	if !u.MustChangePassword {
		if ok, verr := auth.VerifyPassword(u.PasswordHash, oldPassword); verr != nil || !ok {
			return domain.ErrUnauthorized
		}
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return invalidf("%s", err.Error())
	}
	clearedMustChange := u.MustChangePassword
	u.PasswordHash = hash
	u.MustChangePassword = false
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		if err := tx.DeleteUserSessions(ctx, u.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "user.password_change", "user", u.ID.String(),
			map[string]any{"cleared_must_change": clearedMustChange})
	})
	if err != nil {
		return err
	}
	s.log().Info("password changed", "component", "service", "operation", "password_change",
		"user_id", u.ID, "login", u.Login)
	return nil
}

// UpdateOwnPreferences updates the actor's personal UI preferences (theme).
func (s *Services) UpdateOwnPreferences(ctx context.Context, actor *domain.User, theme string) (*domain.User, error) {
	theme = normalizeText(theme)
	if !domain.ValidTheme(theme) {
		return nil, invalidf("theme must be %q or %q", domain.ThemeLight, domain.ThemeDark)
	}
	var out *domain.User
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		u, err := tx.GetUser(ctx, actor.ID)
		if err != nil {
			return err
		}
		if u.Theme == theme {
			out = u
			return nil
		}
		u.Theme = theme
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		out = u
		return s.audit(ctx, tx, actor, "user.preferences", "user", u.ID.String(),
			map[string]any{"theme": theme})
	})
	if err != nil {
		return nil, fmt.Errorf("update preferences: %w", err)
	}
	return out, nil
}

// EnsureBootstrapAdmin creates the first administrator when the users table is
// empty. The generated password is logged once at Warn and the account requires
// a password change on first use. It is a no-op when any user already exists.
// login defaults to DefaultBootstrapLogin when empty.
func (s *Services) EnsureBootstrapAdmin(ctx context.Context, login string) error {
	login = normalizeText(login)
	if login == "" {
		login = DefaultBootstrapLogin
	}
	if !loginRe.MatchString(login) {
		return invalidf("bootstrap login must be 3-64 characters: letters, digits, . _ @ -")
	}
	existing, err := s.Store.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	plain, err := generateBootstrapPassword()
	if err != nil {
		return fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	hash, err := auth.HashPassword(plain)
	if err != nil {
		return fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	u := &domain.User{
		Login: login, DisplayName: login, PasswordHash: hash,
		Role: domain.RoleAdmin, IsActive: true, MustChangePassword: true,
	}
	created := false
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		// Re-check inside the transaction against concurrent starters.
		cur, err := tx.ListUsers(ctx)
		if err != nil {
			return err
		}
		if len(cur) > 0 {
			return nil
		}
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		created = true
		return s.audit(ctx, tx, u, "user.bootstrap", "user", u.ID.String(),
			map[string]any{"login": login, "must_change_password": true, "auto": true})
	})
	if err != nil {
		return fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	if !created {
		return nil
	}
	s.log().Warn("bootstrap administrator created; change this password immediately after login",
		"component", "service", "operation", "bootstrap",
		"login", login, "password", plain, "user_id", u.ID)
	return nil
}

// BootstrapAdmin creates the first administrator with an explicit password.
// Prefer EnsureBootstrapAdmin for normal installs. The account still requires
// a password change on first login.
func (s *Services) BootstrapAdmin(ctx context.Context, login, password, displayName string) (*domain.User, error) {
	login = normalizeText(login)
	if !loginRe.MatchString(login) {
		return nil, invalidf("login must be 3-64 characters: letters, digits, . _ @ -")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, invalidf("%s", err.Error())
	}
	if displayName = normalizeText(displayName); displayName == "" {
		displayName = login
	}
	u := &domain.User{
		Login: login, DisplayName: displayName, PasswordHash: hash,
		Role: domain.RoleAdmin, IsActive: true, MustChangePassword: true,
	}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		existing, err := tx.ListUsers(ctx)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			return conflictf("users already exist; bootstrap is only allowed on an empty installation")
		}
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		return s.audit(ctx, tx, u, "user.bootstrap", "user", u.ID.String(),
			map[string]any{"login": login, "must_change_password": true, "auto": false})
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap admin: %w", err)
	}
	s.log().Warn("bootstrap administrator created with provided password; change it after first login",
		"component", "service", "operation", "bootstrap",
		"login", login, "user_id", u.ID)
	return u, nil
}

func generateBootstrapPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// ~32 URL-safe characters, always longer than the 8-char minimum.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

// userByID is a small helper shared by user-management methods.
func (s *Services) userByID(ctx context.Context, st store.Store, id uuid.UUID) (*domain.User, error) {
	u, err := st.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}
