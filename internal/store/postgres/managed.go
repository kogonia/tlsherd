package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Managed certificates

const managedCertCols = `id, name, display_name, kind, domain_id, notes, created_at, updated_at`

func scanManagedCertificate(r rowScanner) (domain.ManagedCertificate, error) {
	var m domain.ManagedCertificate
	err := r.Scan(&m.ID, &m.Name, &m.DisplayName, &m.Kind, &m.DomainID, &m.Notes,
		&m.CreatedAt, &m.UpdatedAt)
	return m, err
}

func (s *Store) CreateManagedCertificate(ctx context.Context, m *domain.ManagedCertificate) error {
	m.ID = newID(m.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO managed_certificates (id, name, display_name, kind, domain_id, notes)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at`,
		m.ID, m.Name, m.DisplayName, m.Kind, m.DomainID, m.Notes,
	).Scan(&m.CreatedAt, &m.UpdatedAt)
	return mapErr("create managed certificate", err)
}

func (s *Store) GetManagedCertificate(ctx context.Context, id uuid.UUID) (*domain.ManagedCertificate, error) {
	return queryOne(ctx, s.q, "get managed certificate", scanManagedCertificate,
		`SELECT `+managedCertCols+` FROM managed_certificates WHERE id = $1`, id)
}

func (s *Store) GetManagedCertificateByName(ctx context.Context, name string) (*domain.ManagedCertificate, error) {
	return queryOne(ctx, s.q, "get managed certificate by name", scanManagedCertificate,
		`SELECT `+managedCertCols+` FROM managed_certificates WHERE name = $1`, name)
}

// ListManagedCertificates lists managed certificates ordered by name; empty
// filter fields match everything.
func (s *Store) ListManagedCertificates(ctx context.Context, f store.ManagedCertFilter) ([]domain.ManagedCertificate, error) {
	return queryAll(ctx, s.q, "list managed certificates", scanManagedCertificate, `
		SELECT `+managedCertCols+` FROM managed_certificates
		WHERE ($1::text = '' OR kind = $1)
		  AND ($2::uuid IS NULL OR domain_id = $2)
		ORDER BY name`, f.Kind, f.DomainID)
}

// UpdateManagedCertificate updates mutable metadata (display name, domain link, notes).
// Name and kind are immutable. On return m carries updated_at.
func (s *Store) UpdateManagedCertificate(ctx context.Context, m *domain.ManagedCertificate) error {
	err := s.q.QueryRow(ctx, `
		UPDATE managed_certificates
		SET display_name = $2, domain_id = $3, notes = $4, updated_at = now()
		WHERE id = $1
		RETURNING updated_at`,
		m.ID, m.DisplayName, m.DomainID, m.Notes,
	).Scan(&m.UpdatedAt)
	return mapErr("update managed certificate", err)
}

func (s *Store) DeleteManagedCertificate(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete managed certificate",
		`DELETE FROM managed_certificates WHERE id = $1`, id)
}

// Managed certificate versions

const managedVersionCols = `id, managed_cert_id, certificate_id, version, is_current, activated_at,
	deactivated_at, activated_by, reason`

func scanManagedVersion(r rowScanner) (domain.ManagedCertificateVersion, error) {
	var mv domain.ManagedCertificateVersion
	err := r.Scan(&mv.ID, &mv.ManagedCertID, &mv.CertificateID, &mv.Version, &mv.IsCurrent,
		&mv.ActivatedAt, &mv.DeactivatedAt, &mv.ActivatedBy, &mv.Reason)
	return mv, err
}

// ActivateManagedCertificateVersion makes mv the current version of its managed
// certificate and deactivates the previous one, atomically (the managed
// certificate row is locked to serialize concurrent activations).
//
// If mv.Version <= 0 a new version (max+1) is created. If the version already
// exists (rollback), that row is re-activated and its certificate is kept. On
// return mv carries the stored row.
func (s *Store) ActivateManagedCertificateVersion(ctx context.Context, mv *domain.ManagedCertificateVersion) error {
	return s.withTx(ctx, func(q dbtx) error {
		var locked uuid.UUID
		if err := q.QueryRow(ctx,
			`SELECT id FROM managed_certificates WHERE id = $1 FOR UPDATE`,
			mv.ManagedCertID).Scan(&locked); err != nil {
			return mapErr("lock managed certificate", err)
		}

		activatedAt := time.Now()
		if !mv.ActivatedAt.IsZero() {
			activatedAt = mv.ActivatedAt
		}

		if _, err := q.Exec(ctx, `
			UPDATE managed_certificate_versions SET is_current = false, deactivated_at = $2
			WHERE managed_cert_id = $1 AND is_current`, mv.ManagedCertID, activatedAt); err != nil {
			return mapErr("deactivate current managed certificate version", err)
		}

		version := mv.Version
		if version <= 0 {
			if err := q.QueryRow(ctx, `
				SELECT COALESCE(max(version), 0) + 1 FROM managed_certificate_versions
				WHERE managed_cert_id = $1`, mv.ManagedCertID).Scan(&version); err != nil {
				return mapErr("next managed certificate version", err)
			}
		}

		row := q.QueryRow(ctx, `
			INSERT INTO managed_certificate_versions
				(id, managed_cert_id, certificate_id, version, is_current, activated_at, activated_by, reason)
			VALUES ($1, $2, $3, $4, true, $5, $6, $7)
			ON CONFLICT (managed_cert_id, version) DO UPDATE
			SET is_current = true,
			    activated_at = EXCLUDED.activated_at,
			    deactivated_at = NULL,
			    activated_by = EXCLUDED.activated_by,
			    reason = EXCLUDED.reason
			RETURNING `+managedVersionCols,
			newID(mv.ID), mv.ManagedCertID, mv.CertificateID, version, activatedAt, mv.ActivatedBy, mv.Reason)
		got, err := scanManagedVersion(row)
		if err != nil {
			return mapErr("activate managed certificate version", err)
		}
		*mv = got
		return nil
	})
}

func (s *Store) ListManagedCertificateVersions(ctx context.Context, managedCertID uuid.UUID) ([]domain.ManagedCertificateVersion, error) {
	return queryAll(ctx, s.q, "list managed certificate versions", scanManagedVersion,
		`SELECT `+managedVersionCols+` FROM managed_certificate_versions
		 WHERE managed_cert_id = $1 ORDER BY version DESC`, managedCertID)
}

func (s *Store) GetCurrentManagedCertificateVersion(ctx context.Context, managedCertID uuid.UUID) (*domain.ManagedCertificateVersion, error) {
	return queryOne(ctx, s.q, "get current managed certificate version", scanManagedVersion,
		`SELECT `+managedVersionCols+` FROM managed_certificate_versions
		 WHERE managed_cert_id = $1 AND is_current`, managedCertID)
}

// MaxManagedCertVersion returns the highest version of the managed certificate, or 0 if none.
func (s *Store) MaxManagedCertVersion(ctx context.Context, managedCertID uuid.UUID) (int, error) {
	var v int
	err := s.q.QueryRow(ctx,
		`SELECT COALESCE(max(version), 0) FROM managed_certificate_versions WHERE managed_cert_id = $1`,
		managedCertID).Scan(&v)
	return v, mapErr("max managed cert version", err)
}

// Managed certificate <-> server assignment

const managedServerCols = `managed_cert_id, server_id, install_mode, cert_path, key_path, chain_path,
	fullchain_path, restart_override, created_at, updated_at`

func scanManagedCertServer(r rowScanner) (domain.ManagedCertServer, error) {
	var ms domain.ManagedCertServer
	err := r.Scan(&ms.ManagedCertID, &ms.ServerID, &ms.InstallMode, &ms.CertPath, &ms.KeyPath,
		&ms.ChainPath, &ms.FullchainPath, &ms.RestartOverride, &ms.CreatedAt, &ms.UpdatedAt)
	return ms, err
}

// UpsertManagedCertServer inserts or updates the (managed cert, server) assignment.
// An empty InstallMode defaults to "symlink"; an empty RestartOverride is stored as NULL.
func (s *Store) UpsertManagedCertServer(ctx context.Context, ms *domain.ManagedCertServer) error {
	if ms.InstallMode == "" {
		ms.InstallMode = "symlink"
	}
	err := s.q.QueryRow(ctx, `
		INSERT INTO managed_cert_servers (managed_cert_id, server_id, install_mode, cert_path,
			key_path, chain_path, fullchain_path, restart_override)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (managed_cert_id, server_id) DO UPDATE
		SET install_mode = EXCLUDED.install_mode,
		    cert_path = EXCLUDED.cert_path,
		    key_path = EXCLUDED.key_path,
		    chain_path = EXCLUDED.chain_path,
		    fullchain_path = EXCLUDED.fullchain_path,
		    restart_override = EXCLUDED.restart_override,
		    updated_at = now()
		RETURNING created_at, updated_at`,
		ms.ManagedCertID, ms.ServerID, ms.InstallMode, ms.CertPath, ms.KeyPath, ms.ChainPath,
		ms.FullchainPath, nullableJSON(ms.RestartOverride),
	).Scan(&ms.CreatedAt, &ms.UpdatedAt)
	return mapErr("upsert managed cert server", err)
}

func (s *Store) DeleteManagedCertServer(ctx context.Context, managedCertID, serverID uuid.UUID) error {
	return execOne(ctx, s.q, "delete managed cert server",
		`DELETE FROM managed_cert_servers WHERE managed_cert_id = $1 AND server_id = $2`,
		managedCertID, serverID)
}

func (s *Store) GetManagedCertServer(ctx context.Context, managedCertID, serverID uuid.UUID) (*domain.ManagedCertServer, error) {
	return queryOne(ctx, s.q, "get managed cert server", scanManagedCertServer,
		`SELECT `+managedServerCols+` FROM managed_cert_servers
		 WHERE managed_cert_id = $1 AND server_id = $2`, managedCertID, serverID)
}

func (s *Store) ListManagedCertServersByCert(ctx context.Context, managedCertID uuid.UUID) ([]domain.ManagedCertServer, error) {
	return queryAll(ctx, s.q, "list managed cert servers by cert", scanManagedCertServer,
		`SELECT `+managedServerCols+` FROM managed_cert_servers
		 WHERE managed_cert_id = $1 ORDER BY server_id`, managedCertID)
}

func (s *Store) ListManagedCertServersByServer(ctx context.Context, serverID uuid.UUID) ([]domain.ManagedCertServer, error) {
	return queryAll(ctx, s.q, "list managed cert servers by server", scanManagedCertServer,
		`SELECT `+managedServerCols+` FROM managed_cert_servers
		 WHERE server_id = $1 ORDER BY managed_cert_id`, serverID)
}
