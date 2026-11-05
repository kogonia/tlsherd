package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

const domainCols = `id, fqdn::text, notes, created_at, updated_at`

func scanDomain(r rowScanner) (domain.Domain, error) {
	var d domain.Domain
	err := r.Scan(&d.ID, &d.FQDN, &d.Notes, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

func (s *Store) CreateDomain(ctx context.Context, d *domain.Domain) error {
	d.ID = newID(d.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO domains (id, fqdn, notes) VALUES ($1, $2, $3)
		RETURNING created_at, updated_at`,
		d.ID, d.FQDN, d.Notes,
	).Scan(&d.CreatedAt, &d.UpdatedAt)
	return mapErr("create domain", err)
}

func (s *Store) GetDomain(ctx context.Context, id uuid.UUID) (*domain.Domain, error) {
	return queryOne(ctx, s.q, "get domain", scanDomain,
		`SELECT `+domainCols+` FROM domains WHERE id = $1`, id)
}

func (s *Store) GetDomainByFQDN(ctx context.Context, fqdn string) (*domain.Domain, error) {
	return queryOne(ctx, s.q, "get domain by fqdn", scanDomain,
		`SELECT `+domainCols+` FROM domains WHERE fqdn = $1`, fqdn)
}

func (s *Store) ListDomains(ctx context.Context) ([]domain.Domain, error) {
	return queryAll(ctx, s.q, "list domains", scanDomain,
		`SELECT `+domainCols+` FROM domains ORDER BY fqdn`)
}

func (s *Store) UpdateDomain(ctx context.Context, d *domain.Domain) error {
	err := s.q.QueryRow(ctx, `
		UPDATE domains SET fqdn = $2, notes = $3, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`,
		d.ID, d.FQDN, d.Notes,
	).Scan(&d.UpdatedAt)
	return mapErr("update domain", err)
}

func (s *Store) DeleteDomain(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete domain", `DELETE FROM domains WHERE id = $1`, id)
}

// ListUngroupedDomains returns domains that belong to no group.
func (s *Store) ListUngroupedDomains(ctx context.Context) ([]domain.Domain, error) {
	return queryAll(ctx, s.q, "list ungrouped domains", scanDomain, `
		SELECT `+domainCols+` FROM domains d
		WHERE NOT EXISTS (SELECT 1 FROM domain_groups dg WHERE dg.domain_id = d.id)
		ORDER BY fqdn`)
}
