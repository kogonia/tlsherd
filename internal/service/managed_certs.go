package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/certutil"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Soft problem codes specific to managed certificate replacement.
const (
	CertProblemCNChanged     = "cn_changed"
	CertProblemSANChanged    = "san_changed"
	CertProblemIssuerChanged = "issuer_changed"
	CertProblemKeyChanged    = "public_key_changed"
)

const (
	maxManagedDisplayName = 200
	maxManagedNotes       = 4000
)

// managedNameRe is a DNS-label-like slug. The name doubles as the install
// directory of deployable certificates on agents, so it must stay path-safe.
var managedNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validManagedKind(kind string) bool {
	switch kind {
	case domain.ManagedKindCA, domain.ManagedKindAllowedClient, domain.ManagedKindMTLSClient:
		return true
	}
	return false
}

// ManagedCertInput describes a new managed certificate (metadata only; the
// certificate itself is uploaded with UploadManagedCertificate).
type ManagedCertInput struct {
	Name        string
	DisplayName string
	Kind        string
	DomainIDs   []uuid.UUID
	Notes       string
	// ConfirmCAMismatch accepts linking a CA to domains whose current leaf
	// does not chain to this CA.
	ConfirmCAMismatch bool
}

// ManagedCertPatch holds optional metadata changes. Name and Kind are immutable.
type ManagedCertPatch struct {
	DisplayName *string
	Notes       *string
	// DomainIDs, when non-nil, replaces the full set of linked domains
	// (empty slice clears all links; administrators only).
	DomainIDs *[]uuid.UUID
	// ConfirmCAMismatch accepts CA↔domain links when the domain leaf does not
	// chain to this CA (kind=ca only).
	ConfirmCAMismatch bool
}

// ManagedCertListInput filters ListManagedCertificates.
type ManagedCertListInput struct {
	Kind     string
	DomainID *uuid.UUID
}

// ManagedCertDomainRef is a linked domain shown on a managed certificate view.
type ManagedCertDomainRef struct {
	ID   uuid.UUID `json:"id"`
	FQDN string    `json:"fqdn"`
}

// ManagedCertView is a managed certificate with its current certificate metadata.
type ManagedCertView struct {
	domain.ManagedCertificate
	DomainIDs          []uuid.UUID            `json:"domain_ids"`
	Domains            []ManagedCertDomainRef `json:"domains"`
	HasKey             bool                   `json:"has_key"`
	CurrentVersion     int                    `json:"current_version,omitempty"`
	CurrentCertificate *domain.Certificate    `json:"current_certificate,omitempty"`
	// ServerIDs lists servers the certificate is deployed to (mtls_client only).
	ServerIDs []uuid.UUID `json:"server_ids"`
}

// ManagedCertVersion is one entry of a managed certificate's history.
type ManagedCertVersion struct {
	domain.ManagedCertificateVersion
	Certificate *domain.Certificate `json:"certificate"`
}

// ManagedUploadInput is a PEM bundle for a managed certificate. ca and
// allowed_client kinds take CertPEM (and optional ChainPEM) only; mtls_client
// requires CertPEM and KeyPEM.
type ManagedUploadInput struct {
	CertPEM  []byte
	KeyPEM   []byte
	ChainPEM []byte
	Reason   string

	ConfirmIdentityChange bool
	ConfirmExpired        bool
	ConfirmNotYetValid    bool
	// ConfirmWarnings acknowledges every soft problem in one shot.
	ConfirmWarnings bool
}

// ManagedUploadResult describes the outcome of UploadManagedCertificate.
type ManagedUploadResult struct {
	Certificate  *domain.Certificate               `json:"certificate"`
	Version      *domain.ManagedCertificateVersion `json:"version"`
	ChainWarning string                            `json:"chain_warning,omitempty"`
	// Unchanged is true when the uploaded certificate was already current.
	Unchanged bool `json:"unchanged"`
}

// ManagedCertServerInput describes a managed certificate -> server assignment.
type ManagedCertServerInput struct {
	InstallMode     string
	CertPath        string
	KeyPath         string
	ChainPath       string
	FullchainPath   string
	RestartOverride json.RawMessage
}

// ---------------------------------------------------------------------------
// Authorization

func uniqueUUIDs(ids []uuid.UUID) []uuid.UUID {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[uuid.UUID]struct{}, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// requireManagedWrite allows admins, or operators with can_write_certs on any
// linked domain (unlinked managed certificates are admin only).
func (s *Services) requireManagedWrite(ctx context.Context, st store.Store, actor *domain.User, mc *domain.ManagedCertificate) error {
	if isAdmin(actor) {
		return nil
	}
	ids, err := st.ListManagedCertDomainIDs(ctx, mc.ID)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return forbiddenf("managed certificates without a domain are managed by administrators")
	}
	for _, id := range ids {
		if err := s.requireDomainPerm(ctx, actor, id, permWriteCerts); err == nil {
			return nil
		}
	}
	return forbiddenf("can_write_certs required on a linked domain")
}

// requireManagedRead allows admins, or operators who can read any linked domain.
func (s *Services) requireManagedRead(ctx context.Context, st store.Store, actor *domain.User, mc *domain.ManagedCertificate) error {
	if isAdmin(actor) {
		return nil
	}
	ids, err := st.ListManagedCertDomainIDs(ctx, mc.ID)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return forbiddenf("managed certificate not accessible")
	}
	for _, id := range ids {
		if err := s.requireDomainPerm(ctx, actor, id, permRead); err == nil {
			return nil
		}
	}
	return forbiddenf("managed certificate not accessible")
}

// requireDomainIDsExistAndWritable checks each domain exists and (for operators)
// that the actor has can_write_certs. An empty set is allowed only for admins.
func (s *Services) requireDomainIDsExistAndWritable(ctx context.Context, st store.Store, actor *domain.User, domainIDs []uuid.UUID) error {
	if len(domainIDs) == 0 {
		return requireAdmin(actor)
	}
	for _, id := range domainIDs {
		if _, err := st.GetDomain(ctx, id); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return invalidf("domain does not exist")
			}
			return err
		}
		if !isAdmin(actor) {
			if err := s.requireDomainPerm(ctx, actor, id, permWriteCerts); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateCADomainLinks enforces one CA per domain and, when both sides have
// material, that each domain leaf chains to this CA. Soft mismatches need
// confirmCAMismatch; otherwise *CertConfirmationError is returned.
func (s *Services) validateCADomainLinks(ctx context.Context, st store.Store, mc *domain.ManagedCertificate, domainIDs []uuid.UUID, confirmCAMismatch bool) error {
	if mc.Kind != domain.ManagedKindCA || len(domainIDs) == 0 {
		return nil
	}
	var caAnchors linkedCA
	mv, err := st.GetCurrentManagedCertificateVersion(ctx, mc.ID)
	switch {
	case err == nil:
		c, err := st.GetCertificate(ctx, mv.CertificateID)
		if err != nil {
			return err
		}
		p, err := s.loadStoredCert(c.FingerprintSHA256)
		if err != nil {
			return fmt.Errorf("load CA certificate: %w", err)
		}
		caAnchors = linkedCA{Name: mc.Name, Anchors: append([]*x509.Certificate{p.Leaf}, p.Chain...)}
	case !errors.Is(err, domain.ErrNotFound):
		return err
	}

	var problems []CertProblem
	for _, did := range domainIDs {
		others, err := st.ListManagedCertificates(ctx, store.ManagedCertFilter{Kind: domain.ManagedKindCA, DomainID: &did})
		if err != nil {
			return err
		}
		for _, other := range others {
			if other.ID == mc.ID {
				continue
			}
			d, _ := st.GetDomain(ctx, did)
			fqdn := did.String()
			if d != nil {
				fqdn = d.FQDN
			}
			return conflictf("domain %s already has CA %q linked; unlink it first (one CA per domain)", fqdn, other.Name)
		}
		if len(caAnchors.Anchors) == 0 {
			continue
		}
		dc, err := st.GetCurrentDomainCertificate(ctx, did)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return err
		}
		leafCert, err := st.GetCertificate(ctx, dc.CertificateID)
		if err != nil {
			return err
		}
		parsed, err := s.loadStoredCert(leafCert.FingerprintSHA256)
		if err != nil {
			s.log().Warn("cannot load domain certificate for CA link check", "component", "service",
				"operation", "validate_ca_domain_links", "domain_id", did, "error", err)
			continue
		}
		if caMatches([]linkedCA{caAnchors}, parsed.Leaf, parsed.Chain) {
			continue
		}
		d, _ := st.GetDomain(ctx, did)
		fqdn := did.String()
		if d != nil {
			fqdn = d.FQDN
		}
		problems = append(problems, CertProblem{
			Code:    CertProblemCAMismatch,
			Message: fmt.Sprintf("current certificate of %s is not signed by CA %q", fqdn, mc.Name),
		})
	}
	if len(problems) == 0 || confirmCAMismatch {
		return nil
	}
	return &CertConfirmationError{
		Problems:        problems,
		ManagedCertName: mc.Name,
	}
}

// syncLinkedDomainCAEvents refreshes cert_ca_mismatch for every domain in ids
// (and resolves it when the leaf matches or the domain has no leaf).
func (s *Services) syncLinkedDomainCAEvents(ctx context.Context, st store.Store, domainIDs []uuid.UUID) error {
	for _, did := range domainIDs {
		d, err := st.GetDomain(ctx, did)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return err
		}
		dc, err := st.GetCurrentDomainCertificate(ctx, did)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				if err := s.resolve(ctx, st, DedupKey(EvCertCAMismatch, did.String()), "ca_unlinked"); err != nil {
					return err
				}
				continue
			}
			return err
		}
		c, err := st.GetCertificate(ctx, dc.CertificateID)
		if err != nil {
			return err
		}
		if err := s.scanDomainCAStore(ctx, st, d, c); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// CRUD

// CreateManagedCertificate creates the metadata record of a managed
// certificate. Operators need can_write_certs on every linked domain;
// creating with no domains is admin-only.
func (s *Services) CreateManagedCertificate(ctx context.Context, actor *domain.User, in ManagedCertInput) (*ManagedCertView, error) {
	name := normalizeText(in.Name)
	if !managedNameRe.MatchString(name) {
		return nil, invalidf("name must be a lowercase slug (a-z, 0-9, '-'; 1-63 characters)")
	}
	if !validManagedKind(in.Kind) {
		return nil, invalidf("kind must be one of ca, allowed_client, mtls_client")
	}
	display, notes := normalizeText(in.DisplayName), normalizeText(in.Notes)
	if len(display) > maxManagedDisplayName {
		return nil, invalidf("display_name exceeds %d bytes", maxManagedDisplayName)
	}
	if len(notes) > maxManagedNotes {
		return nil, invalidf("notes exceed %d bytes", maxManagedNotes)
	}
	domainIDs := uniqueUUIDs(in.DomainIDs)
	mc := &domain.ManagedCertificate{
		Name: name, DisplayName: display, Kind: in.Kind, Notes: notes,
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if err := s.requireDomainIDsExistAndWritable(ctx, tx, actor, domainIDs); err != nil {
			return err
		}
		// The name is an agent install directory next to domain directories.
		if _, err := tx.GetDomainByFQDN(ctx, name); err == nil {
			return conflictf("name is already used by a domain")
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err := tx.CreateManagedCertificate(ctx, mc); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				return conflictf("managed certificate name already exists")
			}
			return err
		}
		// CA exclusivity / leaf match: validate after create so mc.ID is set;
		// roll back the whole tx on failure.
		if err := s.validateCADomainLinks(ctx, tx, mc, domainIDs, in.ConfirmCAMismatch); err != nil {
			return err
		}
		if err := tx.SetManagedCertDomains(ctx, mc.ID, domainIDs); err != nil {
			return err
		}
		if err := s.syncLinkedDomainCAEvents(ctx, tx, domainIDs); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "managed_certificate.create", "managed_certificate", mc.ID.String(),
			map[string]any{"name": mc.Name, "kind": mc.Kind, "domain_ids": domainIDs})
	})
	if err != nil {
		return nil, fmt.Errorf("create managed certificate: %w", err)
	}
	return s.buildManagedView(ctx, *mc)
}

// GetManagedCertificate returns a managed certificate view. Requires read access.
func (s *Services) GetManagedCertificate(ctx context.Context, actor *domain.User, id uuid.UUID) (*ManagedCertView, error) {
	mc, err := s.Store.GetManagedCertificate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get managed certificate: %w", err)
	}
	if err := s.requireManagedRead(ctx, s.Store, actor, mc); err != nil {
		return nil, err
	}
	return s.buildManagedView(ctx, *mc)
}

// ListManagedCertificates lists managed certificates visible to actor
// (admins: all; operators: those linked to at least one readable domain).
func (s *Services) ListManagedCertificates(ctx context.Context, actor *domain.User, in ManagedCertListInput) ([]ManagedCertView, error) {
	if in.Kind != "" && !validManagedKind(in.Kind) {
		return nil, invalidf("unknown kind %q", in.Kind)
	}
	var visible map[uuid.UUID]struct{}
	if !isAdmin(actor) {
		ids, err := s.Authz.VisibleDomainIDs(ctx, actor)
		if err != nil {
			return nil, fmt.Errorf("list managed certificates: %w", err)
		}
		visible = make(map[uuid.UUID]struct{}, len(ids))
		for _, id := range ids {
			visible[id] = struct{}{}
		}
	}
	all, err := s.Store.ListManagedCertificates(ctx, store.ManagedCertFilter{Kind: in.Kind, DomainID: in.DomainID})
	if err != nil {
		return nil, fmt.Errorf("list managed certificates: %w", err)
	}
	out := make([]ManagedCertView, 0, len(all))
	for _, mc := range all {
		v, err := s.buildManagedView(ctx, mc)
		if err != nil {
			return nil, fmt.Errorf("list managed certificates: %w", err)
		}
		if visible != nil {
			ok := false
			for _, did := range v.DomainIDs {
				if _, hit := visible[did]; hit {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, *v)
	}
	return out, nil
}

// UpdateManagedCertificate patches display name, notes and linked domains.
// Operators need can_write_certs on a currently linked domain and on every
// domain in a replacement set; clearing all links is admin-only.
func (s *Services) UpdateManagedCertificate(ctx context.Context, actor *domain.User, id uuid.UUID, p ManagedCertPatch) (*ManagedCertView, error) {
	var out *domain.ManagedCertificate
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		mc, err := tx.GetManagedCertificate(ctx, id)
		if err != nil {
			return err
		}
		if err := s.requireManagedWrite(ctx, tx, actor, mc); err != nil {
			return err
		}
		changes := map[string]any{}
		if p.DisplayName != nil {
			v := normalizeText(*p.DisplayName)
			if len(v) > maxManagedDisplayName {
				return invalidf("display_name exceeds %d bytes", maxManagedDisplayName)
			}
			mc.DisplayName = v
			changes["display_name"] = v
		}
		if p.Notes != nil {
			v := normalizeText(*p.Notes)
			if len(v) > maxManagedNotes {
				return invalidf("notes exceed %d bytes", maxManagedNotes)
			}
			mc.Notes = v
			changes["notes"] = v
		}
		var prevDomainIDs []uuid.UUID
		if p.DomainIDs != nil {
			domainIDs := uniqueUUIDs(*p.DomainIDs)
			if err := s.requireDomainIDsExistAndWritable(ctx, tx, actor, domainIDs); err != nil {
				return err
			}
			var err error
			prevDomainIDs, err = tx.ListManagedCertDomainIDs(ctx, mc.ID)
			if err != nil {
				return err
			}
			if err := s.validateCADomainLinks(ctx, tx, mc, domainIDs, p.ConfirmCAMismatch); err != nil {
				return err
			}
			if err := tx.SetManagedCertDomains(ctx, mc.ID, domainIDs); err != nil {
				return err
			}
			// Refresh CA match events for domains that were added or removed.
			touched := uniqueUUIDs(append(append([]uuid.UUID{}, prevDomainIDs...), domainIDs...))
			if err := s.syncLinkedDomainCAEvents(ctx, tx, touched); err != nil {
				return err
			}
			changes["domain_ids"] = domainIDs
		}
		if len(changes) == 0 {
			out = mc
			return nil
		}
		if p.DisplayName != nil || p.Notes != nil {
			if err := tx.UpdateManagedCertificate(ctx, mc); err != nil {
				return err
			}
		}
		out = mc
		return s.audit(ctx, tx, actor, "managed_certificate.update", "managed_certificate", id.String(), changes)
	})
	if err != nil {
		return nil, fmt.Errorf("update managed certificate: %w", err)
	}
	return s.buildManagedView(ctx, *out)
}

// DeleteManagedCertificate removes a managed certificate with its history and
// server assignments; stored certificate files that nothing else references
// are deleted too. Endpoints using it as client certificate lose the link.
func (s *Services) DeleteManagedCertificate(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	var orphans []string
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		mc, err := tx.GetManagedCertificate(ctx, id)
		if err != nil {
			return err
		}
		if err := s.requireManagedWrite(ctx, tx, actor, mc); err != nil {
			return err
		}
		versions, err := tx.ListManagedCertificateVersions(ctx, id)
		if err != nil {
			return err
		}
		if err := tx.DeleteManagedCertificate(ctx, id); err != nil {
			return err
		}
		for _, v := range versions {
			ref, err := tx.CertificateReferenced(ctx, v.CertificateID)
			if err != nil {
				return err
			}
			if ref {
				continue
			}
			c, err := tx.GetCertificate(ctx, v.CertificateID)
			if err != nil {
				return err
			}
			if err := tx.DeleteCertificate(ctx, c.ID); err != nil {
				return err
			}
			orphans = append(orphans, c.FingerprintSHA256)
		}
		for _, t := range []string{EvCertExpired, EvCertExpiringSoon} {
			if err := s.resolve(ctx, tx, managedDedupKey(t, id), "managed_certificate_deleted"); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, actor, "managed_certificate.delete", "managed_certificate", id.String(),
			map[string]any{"name": mc.Name, "kind": mc.Kind})
	})
	if err != nil {
		return fmt.Errorf("delete managed certificate: %w", err)
	}
	for _, fp := range orphans {
		if err := s.removeCertFiles(fp); err != nil {
			s.log().Warn("remove certificate files failed", "component", "service",
				"operation", "delete_managed_certificate", "fingerprint", fp, "error", err)
		}
	}
	return nil
}

func managedDedupKey(eventType string, id uuid.UUID) string {
	return DedupKey(eventType, "managed:"+id.String())
}

func (s *Services) buildManagedView(ctx context.Context, mc domain.ManagedCertificate) (*ManagedCertView, error) {
	v := &ManagedCertView{
		ManagedCertificate: mc,
		DomainIDs:          []uuid.UUID{},
		Domains:            []ManagedCertDomainRef{},
		ServerIDs:          []uuid.UUID{},
	}
	ids, err := s.Store.ListManagedCertDomainIDs(ctx, mc.ID)
	if err != nil {
		return nil, err
	}
	v.DomainIDs = ids
	for _, did := range ids {
		d, err := s.Store.GetDomain(ctx, did)
		switch {
		case err == nil:
			v.Domains = append(v.Domains, ManagedCertDomainRef{ID: d.ID, FQDN: d.FQDN})
		case !errors.Is(err, domain.ErrNotFound):
			return nil, err
		}
	}
	mv, err := s.Store.GetCurrentManagedCertificateVersion(ctx, mc.ID)
	switch {
	case err == nil:
		c, err := s.Store.GetCertificate(ctx, mv.CertificateID)
		if err != nil {
			return nil, err
		}
		v.CurrentVersion, v.CurrentCertificate, v.HasKey = mv.Version, c, c.KeyPath != ""
	case !errors.Is(err, domain.ErrNotFound):
		return nil, err
	}
	if mc.Kind == domain.ManagedKindMTLSClient {
		sss, err := s.Store.ListManagedCertServersByCert(ctx, mc.ID)
		if err != nil {
			return nil, err
		}
		for _, ss := range sss {
			v.ServerIDs = append(v.ServerIDs, ss.ServerID)
		}
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Upload / versions

// parseManagedUpload validates the PEM material for the kind.
func parseManagedUpload(kind string, in ManagedUploadInput, now time.Time) (*certutil.Parsed, error) {
	for _, f := range [][]byte{in.CertPEM, in.KeyPEM, in.ChainPEM} {
		if len(f) > MaxPEMBytes {
			return nil, invalidf("PEM file exceeds %d bytes", MaxPEMBytes)
		}
	}
	if len(in.CertPEM) == 0 {
		return nil, invalidf("cert is required")
	}
	if kind == domain.ManagedKindMTLSClient {
		if len(in.KeyPEM) == 0 {
			return nil, invalidf("cert and key are required for mtls_client certificates")
		}
		p, err := certutil.ParseBundle(in.CertPEM, in.KeyPEM, in.ChainPEM, now)
		if err != nil {
			if errors.Is(err, certutil.ErrKeyMismatch) {
				return nil, &userError{kind: domain.ErrKeyCertMismatch, msg: domain.ErrKeyCertMismatch.Error()}
			}
			return nil, invalidf("certificate bundle rejected: %s", err.Error())
		}
		return p, nil
	}
	if len(in.KeyPEM) > 0 {
		return nil, invalidf("%s certificates are stored without a private key", kind)
	}
	p, err := certutil.ParseCertOnly(in.CertPEM, in.ChainPEM, now)
	if err != nil {
		return nil, invalidf("certificate rejected: %s", err.Error())
	}
	return p, nil
}

// identityChanges lists soft problems for replacing cur with p: subject CN,
// SANs, issuer or public key (SPKI) differ.
func identityChanges(cur *domain.Certificate, curSPKI string, p *certutil.Parsed, newSPKI string) []CertProblem {
	var out []CertProblem
	if cur.SubjectCN != p.SubjectCN {
		out = append(out, CertProblem{Code: CertProblemCNChanged,
			Message: fmt.Sprintf("subject CN changes from %q to %q", cur.SubjectCN, p.SubjectCN)})
	}
	if !slices.Equal(slices.Sorted(slices.Values(cur.SANs)), slices.Sorted(slices.Values(p.SANs))) {
		out = append(out, CertProblem{Code: CertProblemSANChanged,
			Message: fmt.Sprintf("SANs change from %v to %v", cur.SANs, p.SANs)})
	}
	if cur.IssuerCN != p.IssuerCN {
		out = append(out, CertProblem{Code: CertProblemIssuerChanged,
			Message: fmt.Sprintf("issuer changes from %q to %q", cur.IssuerCN, p.IssuerCN)})
	}
	if curSPKI != "" && newSPKI != "" && curSPKI != newSPKI {
		out = append(out, CertProblem{Code: CertProblemKeyChanged,
			Message: "public key (SPKI fingerprint) differs from the current certificate"})
	}
	return out
}

// UploadManagedCertificate stores a new current version. Soft problems
// (expired, not yet valid, CN/SAN/issuer/public key differ from the current
// version) need confirmation flags (or ConfirmWarnings); otherwise
// *CertConfirmationError is returned. Requires write access.
func (s *Services) UploadManagedCertificate(ctx context.Context, actor *domain.User, id uuid.UUID, in ManagedUploadInput) (*ManagedUploadResult, error) {
	mc, err := s.Store.GetManagedCertificate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("upload managed certificate: %w", err)
	}
	if err := s.requireManagedWrite(ctx, s.Store, actor, mc); err != nil {
		return nil, err
	}
	now := s.now()
	parsed, err := parseManagedUpload(mc.Kind, in, now)
	if err != nil {
		return nil, err
	}
	newSPKI, err := certutil.PublicKeyFingerprint(parsed.Leaf)
	if err != nil {
		return nil, invalidf("unsupported public key: %s", err.Error())
	}

	var (
		current *domain.Certificate
		curSPKI string
		curMV   *domain.ManagedCertificateVersion
	)
	switch mv, err := s.Store.GetCurrentManagedCertificateVersion(ctx, mc.ID); {
	case err == nil:
		curMV = mv
		if current, err = s.Store.GetCertificate(ctx, mv.CertificateID); err != nil {
			return nil, fmt.Errorf("upload managed certificate: %w", err)
		}
	case errors.Is(err, domain.ErrNotFound):
	default:
		return nil, fmt.Errorf("upload managed certificate: %w", err)
	}
	if current != nil && current.FingerprintSHA256 == parsed.Fingerprint {
		return &ManagedUploadResult{Certificate: current, Version: curMV, Unchanged: true}, nil
	}
	if current != nil {
		stored, lerr := s.loadStoredCert(current.FingerprintSHA256)
		if lerr == nil {
			curSPKI, lerr = certutil.PublicKeyFingerprint(stored.Leaf)
		}
		if lerr != nil {
			curSPKI = ""
			s.log().Warn("cannot derive public key of current managed certificate; skipping SPKI comparison",
				"component", "service", "operation", "upload_managed_certificate",
				"managed_cert_id", mc.ID, "error", lerr)
		}
	}

	confirmExpired := in.ConfirmWarnings || in.ConfirmExpired
	confirmNotYet := in.ConfirmWarnings || in.ConfirmNotYetValid
	confirmChange := in.ConfirmWarnings || in.ConfirmIdentityChange

	var problems, changes []CertProblem
	if current != nil {
		changes = identityChanges(current, curSPKI, parsed, newSPKI)
		if !confirmChange {
			problems = append(problems, changes...)
		}
	}
	if parsed.Expired && !confirmExpired {
		problems = append(problems, CertProblem{Code: CertProblemExpired,
			Message: fmt.Sprintf("certificate expired at %s", parsed.NotAfter.Format(time.RFC3339))})
	}
	if parsed.NotYetValid && !confirmNotYet {
		problems = append(problems, CertProblem{Code: CertProblemNotYetValid,
			Message: fmt.Sprintf("certificate not valid until %s", parsed.NotBefore.Format(time.RFC3339))})
	}
	if len(problems) > 0 {
		return nil, &CertConfirmationError{
			Problems: problems, ManagedCertName: mc.Name,
			UploadedSANs: parsed.SANs, UploadedCN: parsed.SubjectCN,
			NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter, CurrentCertificate: current,
		}
	}

	paths, err := s.writeCertFiles(parsed)
	if err != nil {
		return nil, fmt.Errorf("upload managed certificate: %w", err)
	}
	cert := &domain.Certificate{
		FingerprintSHA256: parsed.Fingerprint, SubjectCN: parsed.SubjectCN, SANs: parsed.SANs,
		IssuerCN: parsed.IssuerCN, Serial: parsed.Serial, NotBefore: parsed.NotBefore,
		NotAfter: parsed.NotAfter, KeyAlgo: parsed.KeyAlgo, KeyBits: parsed.KeyBits,
		CertPath: paths.Cert, KeyPath: paths.Key, ChainPath: paths.Chain,
		UploadedAt: now, UploadedBy: actorID(actor),
	}
	reason := normalizeText(in.Reason)
	if reason == "" {
		reason = "upload"
	}
	mv := &domain.ManagedCertificateVersion{
		ManagedCertID: mc.ID, ActivatedAt: now, ActivatedBy: actorID(actor), Reason: truncate(reason, 256),
	}
	soon := s.monitorSettings(ctx).ExpiringSoon
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.UpsertCertificate(ctx, cert); err != nil {
			return err
		}
		mv.CertificateID = cert.ID
		if err := tx.ActivateManagedCertificateVersion(ctx, mv); err != nil {
			return err
		}
		domIDs, err := tx.ListManagedCertDomainIDs(ctx, mc.ID)
		if err != nil {
			return err
		}
		var evDomain *uuid.UUID
		if len(domIDs) > 0 {
			evDomain = &domIDs[0]
		}
		base := domain.Event{
			DomainID: evDomain, CertificateID: &cert.ID, ActorUserID: actorID(actor), Severity: SeverityWarning,
		}
		details := func(extra map[string]any) []byte {
			d := map[string]any{
				"managed_cert_id": mc.ID, "name": mc.Name, "kind": mc.Kind,
				"fingerprint": cert.FingerprintSHA256, "actor": actor.Login,
			}
			for k, v := range extra {
				d[k] = v
			}
			return jsonDetails(d)
		}
		if len(changes) > 0 {
			ev := base
			ev.Type = EvManagedCertChangeOK
			ev.Message = fmt.Sprintf("identity change of managed certificate %s confirmed by %s", mc.Name, actor.Login)
			ev.Details = details(map[string]any{"changes": changes})
			if err := s.emit(ctx, tx, &ev); err != nil {
				return err
			}
		}
		if parsed.Expired {
			ev := base
			ev.Type = EvCertExpiredUploadOK
			ev.Message = fmt.Sprintf("expired certificate (not_after %s) confirmed for managed certificate %s by %s",
				parsed.NotAfter.Format(time.RFC3339), mc.Name, actor.Login)
			ev.Details = details(map[string]any{"not_after": parsed.NotAfter})
			if err := s.emit(ctx, tx, &ev); err != nil {
				return err
			}
		}
		if parsed.NotYetValid {
			ev := base
			ev.Type = EvCertNotYetValidUploadOK
			ev.Message = fmt.Sprintf("not-yet-valid certificate (not_before %s) confirmed for managed certificate %s by %s",
				parsed.NotBefore.Format(time.RFC3339), mc.Name, actor.Login)
			ev.Details = details(map[string]any{"not_before": parsed.NotBefore})
			if err := s.emit(ctx, tx, &ev); err != nil {
				return err
			}
		}
		if !parsed.Expired {
			if err := s.resolve(ctx, tx, managedDedupKey(EvCertExpired, mc.ID), "upload"); err != nil {
				return err
			}
		}
		if !parsed.Expired && parsed.NotAfter.Sub(now) > soon {
			if err := s.resolve(ctx, tx, managedDedupKey(EvCertExpiringSoon, mc.ID), "upload"); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, actor, "managed_certificate.upload", "managed_certificate", mc.ID.String(), map[string]any{
			"name": mc.Name, "kind": mc.Kind, "fingerprint": cert.FingerprintSHA256, "version": mv.Version,
			"identity_change_confirmed": len(changes) > 0,
			"expired_confirmed":         parsed.Expired,
			"not_yet_valid_confirmed":   parsed.NotYetValid,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("upload managed certificate: %w", err)
	}
	res := &ManagedUploadResult{Certificate: cert, Version: mv}
	if mc.Kind == domain.ManagedKindMTLSClient {
		res.ChainWarning = parsed.ChainWarning
	}
	return res, nil
}

// ListManagedCertificateVersions returns the history of a managed
// certificate, newest first. Requires read access.
func (s *Services) ListManagedCertificateVersions(ctx context.Context, actor *domain.User, id uuid.UUID) ([]ManagedCertVersion, error) {
	mc, err := s.Store.GetManagedCertificate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list managed certificate versions: %w", err)
	}
	if err := s.requireManagedRead(ctx, s.Store, actor, mc); err != nil {
		return nil, err
	}
	mvs, err := s.Store.ListManagedCertificateVersions(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list managed certificate versions: %w", err)
	}
	out := make([]ManagedCertVersion, 0, len(mvs))
	for _, mv := range mvs {
		c, err := s.Store.GetCertificate(ctx, mv.CertificateID)
		if err != nil {
			return nil, fmt.Errorf("list managed certificate versions: %w", err)
		}
		out = append(out, ManagedCertVersion{ManagedCertificateVersion: mv, Certificate: c})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Server assignment (mtls_client only)

// ListManagedCertServers lists servers a managed certificate is deployed to.
// Requires read access.
func (s *Services) ListManagedCertServers(ctx context.Context, actor *domain.User, id uuid.UUID) ([]domain.ManagedCertServer, error) {
	mc, err := s.Store.GetManagedCertificate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list managed cert servers: %w", err)
	}
	if err := s.requireManagedRead(ctx, s.Store, actor, mc); err != nil {
		return nil, err
	}
	out, err := s.Store.ListManagedCertServersByCert(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list managed cert servers: %w", err)
	}
	return out, nil
}

// UpsertManagedCertServer assigns an mtls_client managed certificate to a
// server (agents install it from the next poll). Requires write access to the
// certificate; operators must also be able to see the server.
func (s *Services) UpsertManagedCertServer(ctx context.Context, actor *domain.User, id, serverID uuid.UUID, in ManagedCertServerInput) (*domain.ManagedCertServer, error) {
	restart, err := validateInstallAssignment(in.InstallMode, map[string]string{
		"cert_path": in.CertPath, "key_path": in.KeyPath,
		"chain_path": in.ChainPath, "fullchain_path": in.FullchainPath,
	}, in.RestartOverride)
	if err != nil {
		return nil, err
	}
	ms := &domain.ManagedCertServer{
		ManagedCertID: id, ServerID: serverID, InstallMode: in.InstallMode,
		CertPath: in.CertPath, KeyPath: in.KeyPath, ChainPath: in.ChainPath,
		FullchainPath: in.FullchainPath, RestartOverride: restart,
	}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		mc, err := tx.GetManagedCertificate(ctx, id)
		if err != nil {
			return err
		}
		if err := s.requireManagedWrite(ctx, tx, actor, mc); err != nil {
			return err
		}
		if mc.Kind != domain.ManagedKindMTLSClient {
			return invalidf("only mtls_client certificates can be assigned to servers")
		}
		if !isAdmin(actor) {
			if err := s.requireServerRead(ctx, actor, serverID); err != nil {
				return err
			}
		}
		srv, err := tx.GetServer(ctx, serverID)
		if err != nil {
			return err
		}
		if mv, err := tx.GetCurrentManagedCertificateVersion(ctx, id); err == nil {
			c, err := tx.GetCertificate(ctx, mv.CertificateID)
			if err != nil {
				return err
			}
			if c.KeyPath == "" {
				return invalidf("current certificate has no private key; upload cert and key first")
			}
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		_, gerr := tx.GetManagedCertServer(ctx, id, serverID)
		created := errors.Is(gerr, domain.ErrNotFound)
		if gerr != nil && !created {
			return gerr
		}
		if err := tx.UpsertManagedCertServer(ctx, ms); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "managed_cert_server.upsert", "managed_certificate", id.String(), map[string]any{
			"name": mc.Name, "server_id": serverID, "server": srv.Display(),
			"install_mode": ms.InstallMode, "created": created,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("upsert managed cert server: %w", err)
	}
	return ms, nil
}

// RemoveManagedCertServer removes an assignment. Files already installed on
// the host are left in place by the agent.
func (s *Services) RemoveManagedCertServer(ctx context.Context, actor *domain.User, id, serverID uuid.UUID) error {
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		mc, err := tx.GetManagedCertificate(ctx, id)
		if err != nil {
			return err
		}
		if err := s.requireManagedWrite(ctx, tx, actor, mc); err != nil {
			return err
		}
		if err := tx.DeleteManagedCertServer(ctx, id, serverID); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "managed_cert_server.remove", "managed_certificate", id.String(),
			map[string]any{"name": mc.Name, "server_id": serverID})
	})
	if err != nil {
		return fmt.Errorf("remove managed cert server: %w", err)
	}
	return nil
}
