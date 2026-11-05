package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// DomainView is a domain with its groups and current certificate.
type DomainView struct {
	domain.Domain
	GroupIDs           []uuid.UUID         `json:"group_ids"`
	CurrentVersion     int                 `json:"current_version,omitempty"`
	CurrentCertificate *domain.Certificate `json:"current_certificate,omitempty"`
}

// NormalizeFQDN lowercases and validates a domain name.
func NormalizeFQDN(v string) (string, error) {
	v = strings.ToLower(strings.TrimSuffix(normalizeText(v), "."))
	if v == "" || len(v) > 253 || !fqdnRe.MatchString(v) {
		return "", invalidf("invalid domain name %q", v)
	}
	return v, nil
}

func dedupUUIDs(in []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(in))
	out := make([]uuid.UUID, 0, len(in))
	for _, id := range in {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// CreateDomain creates a domain. Groups are optional (access-control only);
// ungrouped domains are visible to admins and can receive certificates/monitoring.
// Admins may assign any groups; operators need can_write_config in every listed
// group, and must assign at least one group (otherwise they could not see the domain).
func (s *Services) CreateDomain(ctx context.Context, actor *domain.User, fqdn, notes string, groupIDs []uuid.UUID) (*DomainView, error) {
	fqdn, err := NormalizeFQDN(fqdn)
	if err != nil {
		return nil, err
	}
	groupIDs = dedupUUIDs(groupIDs)
	if !isAdmin(actor) {
		if len(groupIDs) == 0 {
			return nil, invalidf("operators must assign at least one group")
		}
		_, byGroup, err := s.Authz.Perms(ctx, actor)
		if err != nil {
			return nil, fmt.Errorf("create domain: %w", err)
		}
		for _, gid := range groupIDs {
			if p, ok := byGroup[gid]; !ok || !p.CanWriteConfig {
				return nil, forbiddenf("can_write_config is required in every selected group")
			}
		}
	}
	d := &domain.Domain{FQDN: fqdn, Notes: normalizeText(notes)}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		for _, gid := range groupIDs {
			if _, err := tx.GetGroup(ctx, gid); err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					return invalidf("group %s does not exist", gid)
				}
				return err
			}
		}
		if err := tx.CreateDomain(ctx, d); err != nil {
			return err
		}
		if err := tx.SetDomainGroups(ctx, d.ID, groupIDs); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "domain.create", "domain", d.ID.String(),
			map[string]any{"fqdn": fqdn, "group_ids": groupIDs})
	})
	if err != nil {
		return nil, fmt.Errorf("create domain: %w", err)
	}
	return &DomainView{Domain: *d, GroupIDs: groupIDs}, nil
}

// UpdateDomain changes notes (can_write_config) and/or the group set (admin
// only). A nil groupIDs leaves groups unchanged.
func (s *Services) UpdateDomain(ctx context.Context, actor *domain.User, id uuid.UUID, notes *string, groupIDs *[]uuid.UUID) (*DomainView, error) {
	if err := s.requireDomainPerm(ctx, actor, id, permWriteConfig); err != nil {
		return nil, err
	}
	if groupIDs != nil {
		if err := requireAdmin(actor); err != nil {
			return nil, err
		}
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		d, err := tx.GetDomain(ctx, id)
		if err != nil {
			return err
		}
		changes := map[string]any{}
		if notes != nil {
			d.Notes = normalizeText(*notes)
			changes["notes"] = d.Notes
			if err := tx.UpdateDomain(ctx, d); err != nil {
				return err
			}
		}
		if groupIDs != nil {
			ids := dedupUUIDs(*groupIDs)
			for _, gid := range ids {
				if _, err := tx.GetGroup(ctx, gid); err != nil {
					if errors.Is(err, domain.ErrNotFound) {
						return invalidf("group %s does not exist", gid)
					}
					return err
				}
			}
			if err := tx.SetDomainGroups(ctx, id, ids); err != nil {
				return err
			}
			if len(ids) > 0 {
				if err := s.resolve(ctx, tx, DedupKey(EvDomainUngrouped, id.String()), "user"); err != nil {
					return err
				}
			}
			changes["group_ids"] = ids
		}
		if len(changes) == 0 {
			return nil
		}
		return s.audit(ctx, tx, actor, "domain.update", "domain", id.String(), changes)
	})
	if err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}
	return s.domainView(ctx, id)
}

// DeleteDomain removes a domain and its server symlink tree. Admin only.
// Certificate files and history rows of other domains are untouched.
func (s *Services) DeleteDomain(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	var fqdn string
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		d, err := tx.GetDomain(ctx, id)
		if err != nil {
			return err
		}
		fqdn = d.FQDN
		if err := tx.DeleteDomain(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "domain.delete", "domain", id.String(), map[string]any{"fqdn": d.FQDN})
	})
	if err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}
	if err := s.removeDomainDir(fqdn); err != nil {
		s.log().Warn("remove domain dir failed", "component", "service", "operation", "delete_domain",
			"fqdn", fqdn, "error", err)
	}
	return nil
}

// GetDomain returns a domain view. Requires can_read on the domain.
func (s *Services) GetDomain(ctx context.Context, actor *domain.User, id uuid.UUID) (*DomainView, error) {
	if err := s.requireDomainPerm(ctx, actor, id, permRead); err != nil {
		return nil, err
	}
	return s.domainView(ctx, id)
}

// ListDomains returns the domains visible to actor.
func (s *Services) ListDomains(ctx context.Context, actor *domain.User) ([]DomainView, error) {
	visible, err := s.Authz.VisibleDomainIDs(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	set := make(map[uuid.UUID]struct{}, len(visible))
	for _, id := range visible {
		set[id] = struct{}{}
	}
	all, err := s.Store.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	out := make([]DomainView, 0, len(set))
	for _, d := range all {
		if _, ok := set[d.ID]; !ok {
			continue
		}
		v, err := s.buildDomainView(ctx, d)
		if err != nil {
			return nil, fmt.Errorf("list domains: %w", err)
		}
		out = append(out, *v)
	}
	return out, nil
}

func (s *Services) domainView(ctx context.Context, id uuid.UUID) (*DomainView, error) {
	d, err := s.Store.GetDomain(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}
	return s.buildDomainView(ctx, *d)
}

func (s *Services) buildDomainView(ctx context.Context, d domain.Domain) (*DomainView, error) {
	gids, err := s.Store.ListDomainGroups(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	v := &DomainView{Domain: d, GroupIDs: gids}
	dc, err := s.Store.GetCurrentDomainCertificate(ctx, d.ID)
	switch {
	case err == nil:
		c, err := s.Store.GetCertificate(ctx, dc.CertificateID)
		if err != nil {
			return nil, err
		}
		v.CurrentVersion = dc.Version
		v.CurrentCertificate = c
	case errors.Is(err, domain.ErrNotFound):
	default:
		return nil, err
	}
	return v, nil
}
