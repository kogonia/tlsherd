package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/authz"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// PermissionInput is one user's permission set inside a group.
type PermissionInput struct {
	UserID         uuid.UUID `json:"user_id"`
	CanRead        bool      `json:"can_read"`
	CanWriteConfig bool      `json:"can_write_config"`
	CanWriteCerts  bool      `json:"can_write_certs"`
}

func validateGroupName(name string) (string, error) {
	name = normalizeText(name)
	if name == "" || len(name) > 128 {
		return "", invalidf("group name must be 1-128 characters")
	}
	return name, nil
}

// CreateGroup creates a group. Admin only.
func (s *Services) CreateGroup(ctx context.Context, actor *domain.User, name, description string) (*domain.Group, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	name, err := validateGroupName(name)
	if err != nil {
		return nil, err
	}
	g := &domain.Group{Name: name, Description: normalizeText(description)}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.CreateGroup(ctx, g); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "group.create", "group", g.ID.String(), map[string]any{"name": g.Name})
	})
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	return g, nil
}

// UpdateGroup renames or re-describes a group. Admin only; nil fields are kept.
func (s *Services) UpdateGroup(ctx context.Context, actor *domain.User, id uuid.UUID, name, description *string) (*domain.Group, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	var out *domain.Group
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		g, err := tx.GetGroup(ctx, id)
		if err != nil {
			return err
		}
		if name != nil {
			n, err := validateGroupName(*name)
			if err != nil {
				return err
			}
			g.Name = n
		}
		if description != nil {
			g.Description = normalizeText(*description)
		}
		if err := tx.UpdateGroup(ctx, g); err != nil {
			return err
		}
		out = g
		return s.audit(ctx, tx, actor, "group.update", "group", id.String(), map[string]any{"name": g.Name})
	})
	if err != nil {
		return nil, fmt.Errorf("update group: %w", err)
	}
	return out, nil
}

// DeleteGroup removes a group. Admin only. Domains that lose their last group
// become admin-only (and are reported by the monitor scan).
func (s *Services) DeleteGroup(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		g, err := tx.GetGroup(ctx, id)
		if err != nil {
			return err
		}
		if err := tx.DeleteGroup(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "group.delete", "group", id.String(), map[string]any{"name": g.Name})
	})
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// GetGroup returns a group. Admins see any group; operators only groups they can read.
func (s *Services) GetGroup(ctx context.Context, actor *domain.User, id uuid.UUID) (*domain.Group, error) {
	if !isAdmin(actor) {
		_, byGroup, err := s.Authz.Perms(ctx, actor)
		if err != nil {
			return nil, fmt.Errorf("get group: %w", err)
		}
		if p, ok := byGroup[id]; !ok || !p.CanRead {
			return nil, forbiddenf("group not accessible")
		}
	}
	g, err := s.Store.GetGroup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	return g, nil
}

// ListGroupsForUser returns all groups for admins and only the readable
// groups for operators.
func (s *Services) ListGroupsForUser(ctx context.Context, actor *domain.User) ([]domain.Group, error) {
	all, err := s.Store.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	if isAdmin(actor) {
		return all, nil
	}
	_, byGroup, err := s.Authz.Perms(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	out := make([]domain.Group, 0, len(byGroup))
	for _, g := range all {
		if p, ok := byGroup[g.ID]; ok && p.CanRead {
			out = append(out, g)
		}
	}
	return out, nil
}

// ListGroupPermissions returns the permission rows of a group. Admin only.
func (s *Services) ListGroupPermissions(ctx context.Context, actor *domain.User, groupID uuid.UUID) ([]domain.GroupPermission, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetGroup(ctx, groupID); err != nil {
		return nil, fmt.Errorf("list group permissions: %w", err)
	}
	ps, err := s.Store.ListGroupPermissions(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("list group permissions: %w", err)
	}
	return ps, nil
}

// SetGroupPermissions replaces the permission set of a group: listed users are
// upserted (can_write_* implies can_read), unlisted users lose access. Admin
// only; the actor's own permissions cannot be changed.
func (s *Services) SetGroupPermissions(ctx context.Context, actor *domain.User, groupID uuid.UUID, in []PermissionInput) ([]domain.GroupPermission, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	seen := make(map[uuid.UUID]struct{}, len(in))
	for _, p := range in {
		if p.UserID == actor.ID {
			return nil, domain.ErrSelfModification
		}
		if _, dup := seen[p.UserID]; dup {
			return nil, invalidf("duplicate user_id %s", p.UserID)
		}
		seen[p.UserID] = struct{}{}
	}
	var out []domain.GroupPermission
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if _, err := tx.GetGroup(ctx, groupID); err != nil {
			return err
		}
		for uid := range seen {
			if _, err := tx.GetUser(ctx, uid); err != nil {
				return err
			}
		}
		current, err := tx.ListGroupPermissions(ctx, groupID)
		if err != nil {
			return err
		}
		for _, c := range current {
			if _, keep := seen[c.UserID]; keep || c.UserID == actor.ID {
				continue
			}
			if err := tx.DeleteGroupPermission(ctx, c.UserID, groupID); err != nil {
				return err
			}
		}
		for _, p := range in {
			gp := domain.GroupPermission{
				UserID: p.UserID, GroupID: groupID,
				CanRead: p.CanRead, CanWriteConfig: p.CanWriteConfig, CanWriteCerts: p.CanWriteCerts,
			}
			authz.NormalizePerm(&gp)
			if !gp.CanRead {
				// An all-false row grants nothing; drop it instead of storing it.
				for _, c := range current {
					if c.UserID == p.UserID {
						if err := tx.DeleteGroupPermission(ctx, p.UserID, groupID); err != nil {
							return err
						}
					}
				}
				continue
			}
			if err := tx.UpsertGroupPermission(ctx, &gp); err != nil {
				return err
			}
			out = append(out, gp)
		}
		return s.audit(ctx, tx, actor, "group.permissions_set", "group", groupID.String(),
			map[string]any{"entries": len(out)})
	})
	if err != nil {
		return nil, fmt.Errorf("set group permissions: %w", err)
	}
	return out, nil
}

// GetDomainGroups returns the groups of a domain. Requires can_read on the domain.
func (s *Services) GetDomainGroups(ctx context.Context, actor *domain.User, domainID uuid.UUID) ([]domain.Group, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permRead); err != nil {
		return nil, err
	}
	ids, err := s.Store.ListDomainGroups(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("get domain groups: %w", err)
	}
	out := make([]domain.Group, 0, len(ids))
	for _, id := range ids {
		g, err := s.Store.GetGroup(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("get domain groups: %w", err)
		}
		out = append(out, *g)
	}
	return out, nil
}

// MyPermissions returns the actor's explicit group permissions. Admins have
// implicit full access and get an empty list.
func (s *Services) MyPermissions(ctx context.Context, actor *domain.User) ([]domain.GroupPermission, error) {
	if isAdmin(actor) {
		return []domain.GroupPermission{}, nil
	}
	ps, err := s.Store.ListUserPermissions(ctx, actor.ID)
	if err != nil {
		return nil, fmt.Errorf("my permissions: %w", err)
	}
	return ps, nil
}
