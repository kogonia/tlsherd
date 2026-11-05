package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

const groupCols = `id, name::text, description, created_at`

func scanGroup(r rowScanner) (domain.Group, error) {
	var g domain.Group
	err := r.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	return g, err
}

func (s *Store) CreateGroup(ctx context.Context, g *domain.Group) error {
	g.ID = newID(g.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO groups (id, name, description) VALUES ($1, $2, $3)
		RETURNING created_at`,
		g.ID, g.Name, g.Description,
	).Scan(&g.CreatedAt)
	return mapErr("create group", err)
}

func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (*domain.Group, error) {
	return queryOne(ctx, s.q, "get group", scanGroup,
		`SELECT `+groupCols+` FROM groups WHERE id = $1`, id)
}

func (s *Store) ListGroups(ctx context.Context) ([]domain.Group, error) {
	return queryAll(ctx, s.q, "list groups", scanGroup,
		`SELECT `+groupCols+` FROM groups ORDER BY name`)
}

func (s *Store) UpdateGroup(ctx context.Context, g *domain.Group) error {
	return execOne(ctx, s.q, "update group",
		`UPDATE groups SET name = $2, description = $3 WHERE id = $1`,
		g.ID, g.Name, g.Description)
}

func (s *Store) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete group", `DELETE FROM groups WHERE id = $1`, id)
}

// SetDomainGroups atomically replaces the set of groups assigned to a domain.
func (s *Store) SetDomainGroups(ctx context.Context, domainID uuid.UUID, groupIDs []uuid.UUID) error {
	return s.withTx(ctx, func(q dbtx) error {
		if _, err := q.Exec(ctx, `DELETE FROM domain_groups WHERE domain_id = $1`, domainID); err != nil {
			return mapErr("clear domain groups", err)
		}
		if len(groupIDs) == 0 {
			return nil
		}
		_, err := q.Exec(ctx, `
			INSERT INTO domain_groups (domain_id, group_id)
			SELECT $1, g FROM unnest($2::uuid[]) AS g
			ON CONFLICT DO NOTHING`,
			domainID, groupIDs)
		return mapErr("set domain groups", err)
	})
}

func scanUUID(r rowScanner) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.Scan(&id)
	return id, err
}

func (s *Store) ListDomainGroups(ctx context.Context, domainID uuid.UUID) ([]uuid.UUID, error) {
	return queryAll(ctx, s.q, "list domain groups", scanUUID,
		`SELECT group_id FROM domain_groups WHERE domain_id = $1 ORDER BY group_id`, domainID)
}

func (s *Store) ListGroupDomains(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	return queryAll(ctx, s.q, "list group domains", scanUUID,
		`SELECT domain_id FROM domain_groups WHERE group_id = $1 ORDER BY domain_id`, groupID)
}

// Permissions

const permCols = `id, user_id, group_id, can_read, can_write_config, can_write_certs, created_at, updated_at`

func scanPermission(r rowScanner) (domain.GroupPermission, error) {
	var p domain.GroupPermission
	err := r.Scan(&p.ID, &p.UserID, &p.GroupID, &p.CanRead, &p.CanWriteConfig,
		&p.CanWriteCerts, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// UpsertGroupPermission inserts or updates the (user, group) permission row.
// On return p carries the stored ID and timestamps.
func (s *Store) UpsertGroupPermission(ctx context.Context, p *domain.GroupPermission) error {
	err := s.q.QueryRow(ctx, `
		INSERT INTO group_permissions (id, user_id, group_id, can_read, can_write_config, can_write_certs)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, group_id) DO UPDATE
		SET can_read = EXCLUDED.can_read,
		    can_write_config = EXCLUDED.can_write_config,
		    can_write_certs = EXCLUDED.can_write_certs,
		    updated_at = now()
		RETURNING id, created_at, updated_at`,
		newID(p.ID), p.UserID, p.GroupID, p.CanRead, p.CanWriteConfig, p.CanWriteCerts,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	return mapErr("upsert group permission", err)
}

func (s *Store) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]domain.GroupPermission, error) {
	return queryAll(ctx, s.q, "list user permissions", scanPermission,
		`SELECT `+permCols+` FROM group_permissions WHERE user_id = $1 ORDER BY group_id`, userID)
}

func (s *Store) DeleteGroupPermission(ctx context.Context, userID, groupID uuid.UUID) error {
	return execOne(ctx, s.q, "delete group permission",
		`DELETE FROM group_permissions WHERE user_id = $1 AND group_id = $2`, userID, groupID)
}

func (s *Store) ListGroupPermissions(ctx context.Context, groupID uuid.UUID) ([]domain.GroupPermission, error) {
	return queryAll(ctx, s.q, "list group permissions", scanPermission,
		`SELECT `+permCols+` FROM group_permissions WHERE group_id = $1 ORDER BY user_id`, groupID)
}
