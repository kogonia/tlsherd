package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/certutil"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// loadStoredCert parses the certificate (and chain, when present) stored under
// certs/<fingerprint>. It needs no private key.
func (s *Services) loadStoredCert(fp string) (*certutil.Parsed, error) {
	certPEM, err := s.readCertFile(fp, certFileName)
	if err != nil {
		return nil, err
	}
	chainPEM, err := s.readCertFile(fp, chainFileName)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	p, err := certutil.ParseCertOnly(certPEM, chainPEM, s.now())
	if err != nil {
		return nil, fmt.Errorf("parse stored certificate: %w", err)
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// Domain leaf vs linked CA

// linkedCA is a CA managed certificate linked to a domain together with its
// trust anchors (the stored certificate and any bundled chain certificates).
type linkedCA struct {
	Name    string
	Anchors []*x509.Certificate
}

// linkedCAs loads the anchors of every kind=ca managed certificate linked to
// the domain that has a readable current version. Unreadable ones are logged
// and skipped, so a broken CA file never raises a false mismatch.
func (s *Services) linkedCAs(ctx context.Context, st store.Store, domainID uuid.UUID) ([]linkedCA, error) {
	mcs, err := st.ListManagedCertificates(ctx, store.ManagedCertFilter{Kind: domain.ManagedKindCA, DomainID: &domainID})
	if err != nil {
		return nil, err
	}
	var out []linkedCA
	for _, mc := range mcs {
		mv, err := st.GetCurrentManagedCertificateVersion(ctx, mc.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return nil, err
		}
		c, err := st.GetCertificate(ctx, mv.CertificateID)
		if err != nil {
			return nil, err
		}
		p, err := s.loadStoredCert(c.FingerprintSHA256)
		if err != nil {
			s.log().Warn("cannot load linked CA certificate", "component", "service", "operation", "linked_cas",
				"managed_cert_id", mc.ID, "domain_id", domainID, "error", err)
			continue
		}
		out = append(out, linkedCA{Name: mc.Name, Anchors: append([]*x509.Certificate{p.Leaf}, p.Chain...)})
	}
	return out, nil
}

func linkedCANames(cas []linkedCA) []string {
	out := make([]string, len(cas))
	for i, ca := range cas {
		out[i] = ca.Name
	}
	return out
}

// caMatches reports whether leaf chains to at least one linked CA. Only
// signatures are checked (not validity periods), following leaf -> chain
// certificates -> anchor.
func caMatches(cas []linkedCA, leaf *x509.Certificate, chain []*x509.Certificate) bool {
	for _, ca := range cas {
		if certChainsTo(leaf, chain, ca.Anchors) {
			return true
		}
	}
	return false
}

func certChainsTo(leaf *x509.Certificate, chain, anchors []*x509.Certificate) bool {
	if leaf == nil {
		return false
	}
	cur := leaf
	used := make([]bool, len(chain))
	for range len(chain) + 1 {
		for _, a := range anchors {
			if bytes.Equal(cur.Raw, a.Raw) || certutil.SignedBy(cur, a) {
				return true
			}
		}
		next := -1
		for i, c := range chain {
			if !used[i] && !bytes.Equal(c.Raw, cur.Raw) && certutil.SignedBy(cur, c) {
				next = i
				break
			}
		}
		if next < 0 {
			return false
		}
		used[next] = true
		cur = chain[next]
	}
	return false
}

// syncCAMismatchEvent opens cert_ca_mismatch for the domain when the current
// leaf does not chain to its linked CAs, and resolves it otherwise.
func (s *Services) syncCAMismatchEvent(ctx context.Context, st store.Store, d *domain.Domain, cert *domain.Certificate, cas []linkedCA, mismatch bool) error {
	key := DedupKey(EvCertCAMismatch, d.ID.String())
	if !mismatch || len(cas) == 0 {
		return s.resolve(ctx, st, key, "monitor")
	}
	names := linkedCANames(cas)
	return s.emit(ctx, st, &domain.Event{
		Type: EvCertCAMismatch, Severity: SeverityWarning, DomainID: &d.ID, CertificateID: &cert.ID, DedupKey: &key,
		Message: fmt.Sprintf("certificate of %s is not signed by any linked CA (%v)", d.FQDN, names),
		Details: jsonDetails(map[string]any{"fingerprint": cert.FingerprintSHA256, "linked_cas": names}),
	})
}

// scanDomainCA re-checks the current leaf of a domain against its linked CAs.
func (s *Services) scanDomainCA(ctx context.Context, d *domain.Domain, cert *domain.Certificate) error {
	cas, err := s.linkedCAs(ctx, s.Store, d.ID)
	if err != nil {
		return err
	}
	mismatch := false
	if len(cas) > 0 {
		p, err := s.loadStoredCert(cert.FingerprintSHA256)
		if err != nil {
			s.log().Warn("cannot load domain certificate for CA check", "component", "monitor",
				"operation", "scan_ca", "domain", d.FQDN, "error", err)
			return nil
		}
		mismatch = !caMatches(cas, p.Leaf, p.Chain)
	}
	return s.syncCAMismatchEvent(ctx, s.Store, d, cert, cas, mismatch)
}

// ---------------------------------------------------------------------------
// Expiry scans

// expiryTarget is a certificate whose expiry is tracked by cert_expired /
// cert_expiring_soon events under DedupKey(type, Entity).
type expiryTarget struct {
	Entity   string // dedup entity, e.g. "managed:<id>" or "endpoint:<id>"
	Label    string // human description used in messages
	NotAfter time.Time
	DomainID *uuid.UUID
	ServerID *uuid.UUID
	CertID   *uuid.UUID
	Details  map[string]any
}

// syncExpiryEvents raises the matching expiry event for t and resolves the other.
func (s *Services) syncExpiryEvents(ctx context.Context, t expiryTarget, set monitorSettings, now time.Time) error {
	expKey := DedupKey(EvCertExpired, t.Entity)
	soonKey := DedupKey(EvCertExpiringSoon, t.Entity)
	left := t.NotAfter.Sub(now)
	details := map[string]any{"not_after": t.NotAfter}
	for k, v := range t.Details {
		details[k] = v
	}
	switch {
	case left <= 0:
		if err := s.emit(ctx, s.Store, &domain.Event{
			Type: EvCertExpired, Severity: SeverityCritical, DomainID: t.DomainID, ServerID: t.ServerID,
			CertificateID: t.CertID, DedupKey: &expKey,
			Message: fmt.Sprintf("%s expired on %s", t.Label, t.NotAfter.Format(time.RFC3339)),
			Details: jsonDetails(details),
		}); err != nil {
			return err
		}
		return s.resolve(ctx, s.Store, soonKey, "monitor")
	case left <= set.ExpiringSoon:
		sev := SeverityWarning
		if left <= 7*24*time.Hour {
			sev = SeverityCritical
		}
		if err := s.emit(ctx, s.Store, &domain.Event{
			Type: EvCertExpiringSoon, Severity: sev, DomainID: t.DomainID, ServerID: t.ServerID,
			CertificateID: t.CertID, DedupKey: &soonKey,
			Message: fmt.Sprintf("%s expires in %d days", t.Label, int(left.Hours()/24)),
			Details: jsonDetails(details),
		}); err != nil {
			return err
		}
		return s.resolve(ctx, s.Store, expKey, "monitor")
	default:
		return s.resolveExpiryEvents(ctx, s.Store, t.Entity, "monitor")
	}
}

// resolveExpiryEvents closes both expiry events of an entity.
func (s *Services) resolveExpiryEvents(ctx context.Context, st store.Store, entity, resolvedBy string) error {
	for _, typ := range []string{EvCertExpired, EvCertExpiringSoon} {
		if err := s.resolve(ctx, st, DedupKey(typ, entity), resolvedBy); err != nil {
			return err
		}
	}
	return nil
}

// ScanManagedCertificates raises cert_expired / cert_expiring_soon for the
// current version of every managed certificate (dedup "managed:<id>") and
// resolves them when no longer true.
func (s *Services) ScanManagedCertificates(ctx context.Context) error {
	set := s.monitorSettings(ctx)
	mcs, err := s.Store.ListManagedCertificates(ctx, store.ManagedCertFilter{})
	if err != nil {
		return fmt.Errorf("scan managed certificates: %w", err)
	}
	now := s.now()
	for _, mc := range mcs {
		mv, err := s.Store.GetCurrentManagedCertificateVersion(ctx, mc.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return fmt.Errorf("scan managed certificates: %w", err)
		}
		c, err := s.Store.GetCertificate(ctx, mv.CertificateID)
		if err != nil {
			return fmt.Errorf("scan managed certificates: %w", err)
		}
		domIDs, err := s.Store.ListManagedCertDomainIDs(ctx, mc.ID)
		if err != nil {
			return fmt.Errorf("scan managed certificates: %w", err)
		}
		var evDomain *uuid.UUID
		if len(domIDs) > 0 {
			evDomain = &domIDs[0]
		}
		label := fmt.Sprintf("managed certificate %s (%s)", mc.Name, mc.Kind)
		if err := s.syncExpiryEvents(ctx, expiryTarget{
			Entity: "managed:" + mc.ID.String(), Label: label, NotAfter: c.NotAfter,
			DomainID: evDomain, CertID: &c.ID,
			Details: map[string]any{
				"managed_cert_id": mc.ID, "name": mc.Name, "kind": mc.Kind,
				"fingerprint": c.FingerprintSHA256, "domain_ids": domIDs,
			},
		}, set, now); err != nil {
			return err
		}
	}
	return nil
}
