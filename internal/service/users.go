package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/auth"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// CreateUserInput describes a new user.
type CreateUserInput struct {
	Login       string
	DisplayName string
	Password    string
	Role        string
}

// UpdateUserInput holds optional changes; nil fields are left untouched.
type UpdateUserInput struct {
	DisplayName *string
	Role        *string
	IsActive    *bool
}

func validRole(r string) bool { return r == domain.RoleAdmin || r == domain.RoleOperator }

// ListUsers returns all users. Admin only.
func (s *Services) ListUsers(ctx context.Context, actor *domain.User) ([]domain.User, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	us, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return us, nil
}

// GetUser returns one user. Admin only.
func (s *Services) GetUser(ctx context.Context, actor *domain.User, id uuid.UUID) (*domain.User, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return s.userByID(ctx, s.Store, id)
}

// CreateUser creates a user. Admin only.
func (s *Services) CreateUser(ctx context.Context, actor *domain.User, in CreateUserInput) (*domain.User, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	login := normalizeText(in.Login)
	if !loginRe.MatchString(login) {
		return nil, invalidf("login must be 3-64 characters: letters, digits, . _ @ -")
	}
	role := in.Role
	if role == "" {
		role = domain.RoleOperator
	}
	if !validRole(role) {
		return nil, invalidf("role must be %q or %q", domain.RoleAdmin, domain.RoleOperator)
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, invalidf("%s", err.Error())
	}
	display := normalizeText(in.DisplayName)
	if display == "" {
		display = login
	}
	u := &domain.User{Login: login, DisplayName: display, PasswordHash: hash, Role: role, IsActive: true}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "user.create", "user", u.ID.String(),
			map[string]any{"login": u.Login, "role": u.Role})
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// UpdateUser applies in to user id. Invariants: an actor cannot change their
// own role or deactivate themselves; the last active admin cannot be demoted
// or deactivated.
func (s *Services) UpdateUser(ctx context.Context, actor *domain.User, id uuid.UUID, in UpdateUserInput) (*domain.User, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	var out *domain.User
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		u, err := s.userByID(ctx, tx, id)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		revokeSessions := false

		if in.DisplayName != nil {
			name := normalizeText(*in.DisplayName)
			if name == "" {
				return invalidf("display_name must not be empty")
			}
			if name != u.DisplayName {
				changes["display_name"] = name
				u.DisplayName = name
			}
		}
		if in.Role != nil && *in.Role != u.Role {
			if !validRole(*in.Role) {
				return invalidf("role must be %q or %q", domain.RoleAdmin, domain.RoleOperator)
			}
			if id == actor.ID {
				return domain.ErrSelfModification
			}
			changes["role"] = *in.Role
			u.Role = *in.Role
		}
		if in.IsActive != nil && *in.IsActive != u.IsActive {
			if !*in.IsActive && id == actor.ID {
				return domain.ErrSelfModification
			}
			changes["is_active"] = *in.IsActive
			u.IsActive = *in.IsActive
			revokeSessions = !u.IsActive
		}
		if len(changes) == 0 {
			out = u
			return nil
		}
		// Re-check the last-admin invariant against the stored state.
		if err := s.checkLastAdmin(ctx, tx, id, u); err != nil {
			return err
		}
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		if revokeSessions {
			if err := tx.DeleteUserSessions(ctx, id); err != nil {
				return err
			}
		}
		out = u
		return s.audit(ctx, tx, actor, "user.update", "user", id.String(), changes)
	})
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return out, nil
}

// checkLastAdmin fails with ErrLastAdmin when the stored version of the user
// is an active admin, the new version no longer is, and no other active admin exists.
func (s *Services) checkLastAdmin(ctx context.Context, st store.Store, id uuid.UUID, updated *domain.User) error {
	stored, err := st.GetUser(ctx, id)
	if err != nil {
		return err
	}
	wasActiveAdmin := stored.Role == domain.RoleAdmin && stored.IsActive
	stillActiveAdmin := updated != nil && updated.Role == domain.RoleAdmin && updated.IsActive
	if !wasActiveAdmin || stillActiveAdmin {
		return nil
	}
	n, err := st.CountActiveAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return domain.ErrLastAdmin
	}
	return nil
}

// DeleteUser removes a user. An actor cannot delete themselves and the last
// active admin cannot be deleted.
func (s *Services) DeleteUser(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	if id == actor.ID {
		return domain.ErrSelfModification
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		u, err := s.userByID(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := s.checkLastAdmin(ctx, tx, id, nil); err != nil {
			return err
		}
		if err := tx.DeleteUser(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "user.delete", "user", id.String(), map[string]any{"login": u.Login})
	})
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// ResetPassword sets a new password for a user and revokes their sessions. Admin only.
func (s *Services) ResetPassword(ctx context.Context, actor *domain.User, id uuid.UUID, newPassword string) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return invalidf("%s", err.Error())
	}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		u, err := s.userByID(ctx, tx, id)
		if err != nil {
			return err
		}
		u.PasswordHash = hash
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		if err := tx.DeleteUserSessions(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "user.password_reset", "user", id.String(), nil)
	})
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	return nil
}
