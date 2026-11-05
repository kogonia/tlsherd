package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

const certCols = `id, fingerprint_sha256, subject_cn, sans, issuer_cn, serial, not_before, not_after,
	key_algo, key_bits, cert_path, key_path, chain_path, uploaded_at, uploaded_by`

func scanCertificate(r rowScanner) (domain.Certificate, error) {
	var (
		c    domain.Certificate
		sans []byte
	)
	err := r.Scan(&c.ID, &c.FingerprintSHA256, &c.SubjectCN, &sans, &c.IssuerCN, &c.Serial,
		&c.NotBefore, &c.NotAfter, &c.KeyAlgo, &c.KeyBits, &c.CertPath, &c.KeyPath,
		&c.ChainPath, &c.UploadedAt, &c.UploadedBy)
	if err != nil {
		return c, err
	}
	if len(sans) > 0 {
		if err := json.Unmarshal(sans, &c.SANs); err != nil {
			return c, fmt.Errorf("decode sans: %w", err)
		}
	}
	return c, nil
}

// UpsertCertificate inserts c, or refreshes metadata and file paths of the
// existing certificate with the same SHA-256 fingerprint (uploaded_at and
// uploaded_by of the original upload are preserved). On return c carries the
// stored ID and upload metadata.
func (s *Store) UpsertCertificate(ctx context.Context, c *domain.Certificate) error {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	sansJSON, err := json.Marshal(sans)
	if err != nil {
		return fmt.Errorf("postgres: encode sans: %w", err)
	}
	err = s.q.QueryRow(ctx, `
		INSERT INTO certificates (id, fingerprint_sha256, subject_cn, sans, issuer_cn, serial,
			not_before, not_after, key_algo, key_bits, cert_path, key_path, chain_path,
			uploaded_at, uploaded_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, COALESCE($14, now()), $15)
		ON CONFLICT (fingerprint_sha256) DO UPDATE
		SET subject_cn = EXCLUDED.subject_cn,
		    sans = EXCLUDED.sans,
		    issuer_cn = EXCLUDED.issuer_cn,
		    serial = EXCLUDED.serial,
		    not_before = EXCLUDED.not_before,
		    not_after = EXCLUDED.not_after,
		    key_algo = EXCLUDED.key_algo,
		    key_bits = EXCLUDED.key_bits,
		    cert_path = EXCLUDED.cert_path,
		    key_path = EXCLUDED.key_path,
		    chain_path = EXCLUDED.chain_path
		RETURNING id, uploaded_at, uploaded_by`,
		newID(c.ID), c.FingerprintSHA256, c.SubjectCN, sansJSON, c.IssuerCN, c.Serial,
		c.NotBefore, c.NotAfter, c.KeyAlgo, c.KeyBits, c.CertPath, c.KeyPath, c.ChainPath,
		timeOrNil(c.UploadedAt), c.UploadedBy,
	).Scan(&c.ID, &c.UploadedAt, &c.UploadedBy)
	return mapErr("upsert certificate", err)
}

func (s *Store) GetCertificateByFingerprint(ctx context.Context, fp string) (*domain.Certificate, error) {
	return queryOne(ctx, s.q, "get certificate by fingerprint", scanCertificate,
		`SELECT `+certCols+` FROM certificates WHERE fingerprint_sha256 = $1`, fp)
}

func (s *Store) GetCertificate(ctx context.Context, id uuid.UUID) (*domain.Certificate, error) {
	return queryOne(ctx, s.q, "get certificate", scanCertificate,
		`SELECT `+certCols+` FROM certificates WHERE id = $1`, id)
}

// DeleteCertificate removes a certificate row. It returns domain.ErrCertificateInUse
// when domain_certificates still references it.
func (s *Store) DeleteCertificate(ctx context.Context, id uuid.UUID) error {
	tag, err := s.q.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, id)
	if err != nil {
		if isFKViolation(err) {
			return fmt.Errorf("%w: %w", domain.ErrCertificateInUse, err)
		}
		return mapErr("delete certificate", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: delete certificate", domain.ErrNotFound)
	}
	return nil
}

// CertificateInUse reports whether the certificate is current for any domain.
func (s *Store) CertificateInUse(ctx context.Context, id uuid.UUID) (bool, error) {
	var inUse bool
	err := s.q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM domain_certificates WHERE certificate_id = $1 AND is_current)`,
		id).Scan(&inUse)
	return inUse, mapErr("certificate in use", err)
}

// ListExpiringCertificates returns certificates that are current for at least
// one domain and expire at or before the given time, soonest first.
func (s *Store) ListExpiringCertificates(ctx context.Context, before time.Time) ([]domain.Certificate, error) {
	return queryAll(ctx, s.q, "list expiring certificates", scanCertificate, `
		SELECT `+certCols+` FROM certificates c
		WHERE c.not_after <= $1
		  AND EXISTS (SELECT 1 FROM domain_certificates dc
		              WHERE dc.certificate_id = c.id AND dc.is_current)
		ORDER BY c.not_after`, before)
}

// Domain certificates

const domainCertCols = `id, domain_id, certificate_id, version, is_current, activated_at,
	deactivated_at, activated_by, reason`

func scanDomainCertificate(r rowScanner) (domain.DomainCertificate, error) {
	var dc domain.DomainCertificate
	err := r.Scan(&dc.ID, &dc.DomainID, &dc.CertificateID, &dc.Version, &dc.IsCurrent,
		&dc.ActivatedAt, &dc.DeactivatedAt, &dc.ActivatedBy, &dc.Reason)
	return dc, err
}

// ActivateDomainCertificate makes dc the current certificate of its domain and
// deactivates the previous one, atomically (the domain row is locked to
// serialize concurrent activations).
//
// If dc.Version <= 0 a new version (max+1) is created. If the version already
// exists for the domain (rollback), that row is re-activated and its certificate
// is kept. On return dc carries the stored row.
func (s *Store) ActivateDomainCertificate(ctx context.Context, dc *domain.DomainCertificate) error {
	return s.withTx(ctx, func(q dbtx) error {
		var locked uuid.UUID
		if err := q.QueryRow(ctx, `SELECT id FROM domains WHERE id = $1 FOR UPDATE`, dc.DomainID).Scan(&locked); err != nil {
			return mapErr("lock domain", err)
		}

		activatedAt := time.Now()
		if !dc.ActivatedAt.IsZero() {
			activatedAt = dc.ActivatedAt
		}

		if _, err := q.Exec(ctx, `
			UPDATE domain_certificates SET is_current = false, deactivated_at = $2
			WHERE domain_id = $1 AND is_current`, dc.DomainID, activatedAt); err != nil {
			return mapErr("deactivate current domain certificate", err)
		}

		version := dc.Version
		if version <= 0 {
			if err := q.QueryRow(ctx,
				`SELECT COALESCE(max(version), 0) + 1 FROM domain_certificates WHERE domain_id = $1`,
				dc.DomainID).Scan(&version); err != nil {
				return mapErr("next domain certificate version", err)
			}
		}

		row := q.QueryRow(ctx, `
			INSERT INTO domain_certificates
				(id, domain_id, certificate_id, version, is_current, activated_at, activated_by, reason)
			VALUES ($1, $2, $3, $4, true, $5, $6, $7)
			ON CONFLICT (domain_id, version) DO UPDATE
			SET is_current = true,
			    activated_at = EXCLUDED.activated_at,
			    deactivated_at = NULL,
			    activated_by = EXCLUDED.activated_by,
			    reason = EXCLUDED.reason
			RETURNING `+domainCertCols,
			newID(dc.ID), dc.DomainID, dc.CertificateID, version, activatedAt, dc.ActivatedBy, dc.Reason)
		got, err := scanDomainCertificate(row)
		if err != nil {
			return mapErr("activate domain certificate", err)
		}
		*dc = got
		return nil
	})
}

func (s *Store) ListDomainCertificates(ctx context.Context, domainID uuid.UUID) ([]domain.DomainCertificate, error) {
	return queryAll(ctx, s.q, "list domain certificates", scanDomainCertificate,
		`SELECT `+domainCertCols+` FROM domain_certificates WHERE domain_id = $1 ORDER BY version DESC`,
		domainID)
}

func (s *Store) GetCurrentDomainCertificate(ctx context.Context, domainID uuid.UUID) (*domain.DomainCertificate, error) {
	return queryOne(ctx, s.q, "get current domain certificate", scanDomainCertificate,
		`SELECT `+domainCertCols+` FROM domain_certificates WHERE domain_id = $1 AND is_current`,
		domainID)
}

func (s *Store) GetDomainCertificateByVersion(ctx context.Context, domainID uuid.UUID, version int) (*domain.DomainCertificate, error) {
	return queryOne(ctx, s.q, "get domain certificate by version", scanDomainCertificate,
		`SELECT `+domainCertCols+` FROM domain_certificates WHERE domain_id = $1 AND version = $2`,
		domainID, version)
}

// MaxDomainCertVersion returns the highest version of the domain, or 0 if none.
func (s *Store) MaxDomainCertVersion(ctx context.Context, domainID uuid.UUID) (int, error) {
	var v int
	err := s.q.QueryRow(ctx,
		`SELECT COALESCE(max(version), 0) FROM domain_certificates WHERE domain_id = $1`,
		domainID).Scan(&v)
	return v, mapErr("max domain cert version", err)
}