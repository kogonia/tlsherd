package authz

import (
	"context"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

type Resolver struct {
	Store store.Store
}

func (r *Resolver) Perms(ctx context.Context, user *domain.User) (domain.EffectivePerms, map[uuid.UUID]domain.EffectivePerms, error) {
	if user.Role == domain.RoleAdmin {
		groups, err := r.Store.ListGroups(ctx)
		if err != nil {
			return domain.EffectivePerms{}, nil, err
		}
		byGroup := make(map[uuid.UUID]domain.EffectivePerms, len(groups))
		ids := make([]uuid.UUID, 0, len(groups))
		for _, g := range groups {
			ids = append(ids, g.ID)
			byGroup[g.ID] = domain.EffectivePerms{
				CanRead: true, CanWriteConfig: true, CanWriteCerts: true,
				GroupIDs: []uuid.UUID{g.ID},
			}
		}
		return domain.EffectivePerms{
			CanRead: true, CanWriteConfig: true, CanWriteCerts: true, GroupIDs: ids,
		}, byGroup, nil
	}
	perms, err := r.Store.ListUserPermissions(ctx, user.ID)
	if err != nil {
		return domain.EffectivePerms{}, nil, err
	}
	byGroup := make(map[uuid.UUID]domain.EffectivePerms)
	var all domain.EffectivePerms
	for _, p := range perms {
		ep := domain.EffectivePerms{
			CanRead:        p.CanRead || p.CanWriteConfig || p.CanWriteCerts,
			CanWriteConfig: p.CanWriteConfig,
			CanWriteCerts:  p.CanWriteCerts,
			GroupIDs:       []uuid.UUID{p.GroupID},
		}
		byGroup[p.GroupID] = ep
		all.CanRead = all.CanRead || ep.CanRead
		all.CanWriteConfig = all.CanWriteConfig || ep.CanWriteConfig
		all.CanWriteCerts = all.CanWriteCerts || ep.CanWriteCerts
		if ep.CanRead {
			all.GroupIDs = append(all.GroupIDs, p.GroupID)
		}
	}
	return all, byGroup, nil
}

func (r *Resolver) DomainPerms(ctx context.Context, user *domain.User, domainID uuid.UUID) (domain.EffectivePerms, error) {
	if user.Role == domain.RoleAdmin {
		return domain.EffectivePerms{CanRead: true, CanWriteConfig: true, CanWriteCerts: true}, nil
	}
	gids, err := r.Store.ListDomainGroups(ctx, domainID)
	if err != nil {
		return domain.EffectivePerms{}, err
	}
	if len(gids) == 0 {
		return domain.EffectivePerms{}, nil
	}
	perms, err := r.Store.ListUserPermissions(ctx, user.ID)
	if err != nil {
		return domain.EffectivePerms{}, err
	}
	var out domain.EffectivePerms
	set := map[uuid.UUID]struct{}{}
	for _, id := range gids {
		set[id] = struct{}{}
	}
	for _, p := range perms {
		if _, ok := set[p.GroupID]; !ok {
			continue
		}
		out.CanRead = out.CanRead || p.CanRead || p.CanWriteConfig || p.CanWriteCerts
		out.CanWriteConfig = out.CanWriteConfig || p.CanWriteConfig
		out.CanWriteCerts = out.CanWriteCerts || p.CanWriteCerts
	}
	return out, nil
}

func (r *Resolver) VisibleDomainIDs(ctx context.Context, user *domain.User) ([]uuid.UUID, error) {
	if user.Role == domain.RoleAdmin {
		domains, err := r.Store.ListDomains(ctx)
		if err != nil {
			return nil, err
		}
		ids := make([]uuid.UUID, 0, len(domains))
		for _, d := range domains {
			ids = append(ids, d.ID)
		}
		return ids, nil
	}
	_, byGroup, err := r.Perms(ctx, user)
	if err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]struct{}{}
	var ids []uuid.UUID
	for gid, p := range byGroup {
		if !p.CanRead {
			continue
		}
		dids, err := r.Store.ListGroupDomains(ctx, gid)
		if err != nil {
			return nil, err
		}
		for _, id := range dids {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (r *Resolver) CanSeeServer(ctx context.Context, user *domain.User, serverID uuid.UUID) (bool, error) {
	if user.Role == domain.RoleAdmin {
		return true, nil
	}
	visible, err := r.VisibleDomainIDs(ctx, user)
	if err != nil {
		return false, err
	}
	dss, err := r.Store.ListDomainServersByServer(ctx, serverID)
	if err != nil {
		return false, err
	}
	set := map[uuid.UUID]struct{}{}
	for _, id := range visible {
		set[id] = struct{}{}
	}
	for _, ds := range dss {
		if _, ok := set[ds.DomainID]; ok {
			return true, nil
		}
	}
	return false, nil
}

func NormalizePerm(p *domain.GroupPermission) {
	if p.CanWriteConfig || p.CanWriteCerts {
		p.CanRead = true
	}
}
