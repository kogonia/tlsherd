package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/certutil"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Upload size limits per PEM file.
const MaxPEMBytes = 128 << 10

// Certificate parts for DownloadCertificate.
const (
	PartCert  = "cert"
	PartChain = "chain"
	PartKey   = "key"
)

// Soft problem codes returned when upload needs confirmation.
const (
	CertProblemExpired        = "expired"
	CertProblemNotYetValid    = "not_yet_valid"
	CertProblemDomainMismatch = "domain_mismatch"
)

// UploadInput is a certificate bundle in PEM form.
type UploadInput struct {
	CertPEM               []byte
	KeyPEM                []byte
	ChainPEM              []byte
	ConfirmDomainMismatch bool
	ConfirmExpired        bool
	ConfirmNotYetValid    bool
	// ConfirmWarnings acknowledges every soft problem in one shot (UI confirm modal).
	ConfirmWarnings bool
}

// UploadResult describes the outcome of UploadCertificate.
type UploadResult struct {
	Certificate       *domain.Certificate       `json:"certificate"`
	DomainCertificate *domain.DomainCertificate `json:"domain_certificate"`
	ChainWarning      string                    `json:"chain_warning,omitempty"`
	// Unchanged is true when the uploaded certificate was already current.
	Unchanged bool `json:"unchanged"`
}

// CertProblem is one soft issue that requires operator confirmation to install.
type CertProblem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// CertConfirmationError is returned when the bundle parses but has soft issues
// (expired, not yet valid, domain mismatch) that were not confirmed.
type CertConfirmationError struct {
	Problems           []CertProblem       `json:"problems"`
	RequestedDomain    string              `json:"requested_domain"`
	UploadedSANs       []string            `json:"uploaded_sans"`
	UploadedCN         string              `json:"uploaded_cn"`
	NotBefore          time.Time           `json:"not_before"`
	NotAfter           time.Time           `json:"not_after"`
	CurrentCertificate *domain.Certificate `json:"current_certificate,omitempty"`
}

func (e *CertConfirmationError) Error() string {
	return domain.ErrConfirmRequired.Error()
}

func (e *CertConfirmationError) Unwrap() error { return domain.ErrConfirmRequired }

// DomainMismatchError is kept for API/test compatibility; new uploads use
// CertConfirmationError. It still unwraps to ErrDomainMismatch.
type DomainMismatchError struct {
	RequestedDomain    string              `json:"requested_domain"`
	UploadedSANs       []string            `json:"uploaded_sans"`
	UploadedCN         string              `json:"uploaded_cn"`
	CurrentCertificate *domain.Certificate `json:"current_certificate,omitempty"`
}

func (e *DomainMismatchError) Error() string {
	return fmt.Sprintf("%s: certificate does not cover %q", domain.ErrDomainMismatch, e.RequestedDomain)
}

func (e *DomainMismatchError) Unwrap() error { return domain.ErrDomainMismatch }

// CertVersion is one entry of a domain's certificate history.
type CertVersion struct {
	domain.DomainCertificate
	Certificate *domain.Certificate `json:"certificate"`
}

// UploadCertificate validates a PEM bundle and makes it the current
// certificate of the domain (new version). Requires can_write_certs.
//
// Soft issues (expired, not yet valid, domain not covered) require confirmation
// flags or ConfirmWarnings; otherwise *CertConfirmationError is returned.
// Confirmed soft issues are recorded as events naming the actor.
func (s *Services) UploadCertificate(ctx context.Context, actor *domain.User, domainID uuid.UUID, in UploadInput) (*UploadResult, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permWriteCerts); err != nil {
		return nil, err
	}
	d, err := s.Store.GetDomain(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("upload certificate: %w", err)
	}
	for _, f := range [][]byte{in.CertPEM, in.KeyPEM, in.ChainPEM} {
		if len(f) > MaxPEMBytes {
			return nil, invalidf("PEM file exceeds %d bytes", MaxPEMBytes)
		}
	}
	if len(in.CertPEM) == 0 || len(in.KeyPEM) == 0 {
		return nil, invalidf("cert and key are required")
	}

	parsed, err := certutil.ParseBundle(in.CertPEM, in.KeyPEM, in.ChainPEM, s.now())
	if err != nil {
		return nil, s.rejectUpload(ctx, actor, d, err)
	}

	covers := certutil.CoversDomain(parsed.SANs, parsed.SubjectCN, d.FQDN)
	var current *domain.Certificate
	curDC, err := s.Store.GetCurrentDomainCertificate(ctx, d.ID)
	switch {
	case err == nil:
		if current, err = s.Store.GetCertificate(ctx, curDC.CertificateID); err != nil {
			return nil, fmt.Errorf("upload certificate: %w", err)
		}
	case errors.Is(err, domain.ErrNotFound):
		curDC = nil
	default:
		return nil, fmt.Errorf("upload certificate: %w", err)
	}

	confirmExpired := in.ConfirmWarnings || in.ConfirmExpired
	confirmNotYet := in.ConfirmWarnings || in.ConfirmNotYetValid
	confirmMismatch := in.ConfirmWarnings || in.ConfirmDomainMismatch

	var problems []CertProblem
	if parsed.Expired && !confirmExpired {
		problems = append(problems, CertProblem{
			Code: CertProblemExpired,
			Message: fmt.Sprintf("certificate expired at %s",
				parsed.NotAfter.Format(time.RFC3339)),
		})
	}
	if parsed.NotYetValid && !confirmNotYet {
		problems = append(problems, CertProblem{
			Code: CertProblemNotYetValid,
			Message: fmt.Sprintf("certificate not valid until %s",
				parsed.NotBefore.Format(time.RFC3339)),
		})
	}
	if !covers && !confirmMismatch {
		problems = append(problems, CertProblem{
			Code: CertProblemDomainMismatch,
			Message: fmt.Sprintf("certificate does not cover domain %q (CN=%q SANs=%v)",
				d.FQDN, parsed.SubjectCN, parsed.SANs),
		})
	}
	if len(problems) > 0 {
		return nil, &CertConfirmationError{
			Problems:           problems,
			RequestedDomain:    d.FQDN,
			UploadedSANs:       parsed.SANs,
			UploadedCN:         parsed.SubjectCN,
			NotBefore:          parsed.NotBefore,
			NotAfter:           parsed.NotAfter,
			CurrentCertificate: current,
		}
	}

	if current != nil && current.FingerprintSHA256 == parsed.Fingerprint {
		return &UploadResult{Certificate: current, DomainCertificate: curDC, Unchanged: true}, nil
	}

	paths, err := s.writeCertFiles(parsed)
	if err != nil {
		return nil, fmt.Errorf("upload certificate: %w", err)
	}

	cert := &domain.Certificate{
		FingerprintSHA256: parsed.Fingerprint,
		SubjectCN:         parsed.SubjectCN,
		SANs:              parsed.SANs,
		IssuerCN:          parsed.IssuerCN,
		Serial:            parsed.Serial,
		NotBefore:         parsed.NotBefore,
		NotAfter:          parsed.NotAfter,
		KeyAlgo:           parsed.KeyAlgo,
		KeyBits:           parsed.KeyBits,
		CertPath:          paths.Cert,
		KeyPath:           paths.Key,
		ChainPath:         paths.Chain,
		UploadedAt:        s.now(),
		UploadedBy:        actorID(actor),
	}
	dc := &domain.DomainCertificate{
		DomainID:    d.ID,
		ActivatedAt: s.now(),
		ActivatedBy: actorID(actor),
		Reason:      "upload",
	}
	now := s.now()
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.UpsertCertificate(ctx, cert); err != nil {
			return err
		}
		dc.CertificateID = cert.ID
		if err := tx.ActivateDomainCertificate(ctx, dc); err != nil {
			return err
		}
		if !covers {
			if err := s.emit(ctx, tx, &domain.Event{
				Type: EvCertDomainMismatchOK, Severity: SeverityWarning,
				DomainID: &d.ID, CertificateID: &cert.ID, ActorUserID: actorID(actor),
				Message: fmt.Sprintf("certificate for %v confirmed for domain %s by %s", parsed.SANs, d.FQDN, actor.Login),
				Details: jsonDetails(map[string]any{
					"uploaded_sans": parsed.SANs, "uploaded_cn": parsed.SubjectCN,
					"domain": d.FQDN, "fingerprint": cert.FingerprintSHA256, "actor": actor.Login,
				}),
			}); err != nil {
				return err
			}
		}
		if parsed.Expired {
			if err := s.emit(ctx, tx, &domain.Event{
				Type: EvCertExpiredUploadOK, Severity: SeverityWarning,
				DomainID: &d.ID, CertificateID: &cert.ID, ActorUserID: actorID(actor),
				Message: fmt.Sprintf("expired certificate (not_after %s) confirmed for %s by %s",
					parsed.NotAfter.Format(time.RFC3339), d.FQDN, actor.Login),
				Details: jsonDetails(map[string]any{
					"not_after": parsed.NotAfter, "fingerprint": cert.FingerprintSHA256, "actor": actor.Login,
				}),
			}); err != nil {
				return err
			}
		}
		if parsed.NotYetValid {
			if err := s.emit(ctx, tx, &domain.Event{
				Type: EvCertNotYetValidUploadOK, Severity: SeverityWarning,
				DomainID: &d.ID, CertificateID: &cert.ID, ActorUserID: actorID(actor),
				Message: fmt.Sprintf("not-yet-valid certificate (not_before %s) confirmed for %s by %s",
					parsed.NotBefore.Format(time.RFC3339), d.FQDN, actor.Login),
				Details: jsonDetails(map[string]any{
					"not_before": parsed.NotBefore, "fingerprint": cert.FingerprintSHA256, "actor": actor.Login,
				}),
			}); err != nil {
				return err
			}
		}
		chainKey := DedupKey(EvCertChainInvalid, d.ID.String())
		if parsed.ChainWarning != "" {
			if err := s.emit(ctx, tx, &domain.Event{
				Type: EvCertChainInvalid, Severity: SeverityWarning,
				DomainID: &d.ID, CertificateID: &cert.ID, ActorUserID: actorID(actor),
				DedupKey: &chainKey, Message: "certificate chain problem: " + parsed.ChainWarning,
				Details: jsonDetails(map[string]any{"warning": parsed.ChainWarning, "fingerprint": cert.FingerprintSHA256}),
			}); err != nil {
				return err
			}
		} else if err := s.resolve(ctx, tx, chainKey, "upload"); err != nil {
			return err
		}
		for _, t := range []string{EvCertKeyMismatch, EvCertUploadRejected} {
			if err := s.resolve(ctx, tx, DedupKey(t, d.ID.String()), "upload"); err != nil {
				return err
			}
			if err := s.resolveTypeDomain(ctx, tx, t, d.ID, "upload"); err != nil {
				return err
			}
		}
		// Only clear expiry/soon events when the new cert is actually OK for that state.
		if !parsed.Expired {
			if err := s.resolve(ctx, tx, DedupKey(EvCertExpired, d.ID.String()), "upload"); err != nil {
				return err
			}
			if err := s.resolveTypeDomain(ctx, tx, EvCertExpired, d.ID, "upload"); err != nil {
				return err
			}
		}
		soon := s.monitorSettings(ctx).ExpiringSoon
		if !parsed.Expired && parsed.NotAfter.Sub(now) > soon {
			if err := s.resolve(ctx, tx, DedupKey(EvCertExpiringSoon, d.ID.String()), "upload"); err != nil {
				return err
			}
			if err := s.resolveTypeDomain(ctx, tx, EvCertExpiringSoon, d.ID, "upload"); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, actor, "certificate.upload", "domain", d.ID.String(), map[string]any{
			"fingerprint":               cert.FingerprintSHA256,
			"version":                   dc.Version,
			"domain_mismatch_confirmed": !covers,
			"expired_confirmed":         parsed.Expired,
			"not_yet_valid_confirmed":   parsed.NotYetValid,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("upload certificate: %w", err)
	}
	s.linkCurrent(d.FQDN, cert.FingerprintSHA256)
	return &UploadResult{Certificate: cert, DomainCertificate: dc, ChainWarning: parsed.ChainWarning}, nil
}

// rejectUpload records a rejected upload and converts the parse error into a
// client-facing domain error.
func (s *Services) rejectUpload(ctx context.Context, actor *domain.User, d *domain.Domain, parseErr error) error {
	ev := &domain.Event{
		Severity: SeverityWarning, DomainID: &d.ID, ActorUserID: actorID(actor),
		Details: jsonDetails(map[string]any{"error": parseErr.Error(), "actor": actor.Login}),
	}
	var out error
	if errors.Is(parseErr, certutil.ErrKeyMismatch) {
		ev.Type = EvCertKeyMismatch
		key := DedupKey(EvCertKeyMismatch, d.ID.String())
		ev.DedupKey = &key
		ev.Message = "uploaded private key does not match the certificate"
		out = &userError{kind: domain.ErrKeyCertMismatch, msg: domain.ErrKeyCertMismatch.Error()}
	} else {
		ev.Type = EvCertUploadRejected
		key := DedupKey(EvCertUploadRejected, d.ID.String())
		ev.DedupKey = &key
		ev.Message = "certificate upload rejected: " + parseErr.Error()
		out = invalidf("certificate bundle rejected: %s", parseErr.Error())
	}
	if err := s.emit(ctx, s.Store, ev); err != nil {
		s.log().Warn("record rejected upload failed", "component", "service", "operation", "upload_certificate", "error", err)
	}
	return out
}

func (s *Services) linkCurrent(fqdn, fp string) {
	if err := s.linkDomainCurrent(fqdn, fp); err != nil {
		s.log().Error("update domain symlink failed", "component", "service", "operation", "link_current",
			"fqdn", fqdn, "fingerprint", fp, "error", err)
	}
}

// ListCertificateVersions returns the certificate history of a domain, newest
// first. Requires can_read.
func (s *Services) ListCertificateVersions(ctx context.Context, actor *domain.User, domainID uuid.UUID) ([]CertVersion, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permRead); err != nil {
		return nil, err
	}
	dcs, err := s.Store.ListDomainCertificates(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("list certificate versions: %w", err)
	}
	out := make([]CertVersion, 0, len(dcs))
	for _, dc := range dcs {
		c, err := s.Store.GetCertificate(ctx, dc.CertificateID)
		if err != nil {
			return nil, fmt.Errorf("list certificate versions: %w", err)
		}
		out = append(out, CertVersion{DomainCertificate: dc, Certificate: c})
	}
	return out, nil
}

// GetCurrentCertificate returns the current version of a domain. Requires can_read.
func (s *Services) GetCurrentCertificate(ctx context.Context, actor *domain.User, domainID uuid.UUID) (*CertVersion, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permRead); err != nil {
		return nil, err
	}
	dc, err := s.Store.GetCurrentDomainCertificate(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("get current certificate: %w", err)
	}
	c, err := s.Store.GetCertificate(ctx, dc.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("get current certificate: %w", err)
	}
	return &CertVersion{DomainCertificate: *dc, Certificate: c}, nil
}

// Rollback re-activates an earlier version of the domain's certificate.
// Requires can_write_certs. Agents pick the change up on their next poll.
func (s *Services) Rollback(ctx context.Context, actor *domain.User, domainID uuid.UUID, version int, reason string) (*domain.DomainCertificate, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permWriteCerts); err != nil {
		return nil, err
	}
	if version <= 0 {
		return nil, invalidf("version must be positive")
	}
	d, err := s.Store.GetDomain(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}
	target, err := s.Store.GetDomainCertificateByVersion(ctx, domainID, version)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, notFoundf("version %d does not exist for this domain", version)
		}
		return nil, fmt.Errorf("rollback: %w", err)
	}
	if target.IsCurrent {
		return nil, conflictf("version %d is already current", version)
	}
	cert, err := s.Store.GetCertificate(ctx, target.CertificateID)
	if err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}
	reason = normalizeText(reason)
	if reason == "" {
		reason = "rollback"
	}
	dc := &domain.DomainCertificate{
		DomainID: domainID, CertificateID: target.CertificateID, Version: version,
		ActivatedAt: s.now(), ActivatedBy: actorID(actor), Reason: "rollback: " + reason,
	}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.ActivateDomainCertificate(ctx, dc); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, &domain.Event{
			Type: EvCertRollback, Severity: SeverityWarning, DomainID: &d.ID, CertificateID: &cert.ID,
			ActorUserID: actorID(actor),
			Message:     fmt.Sprintf("domain %s rolled back to version %d by %s", d.FQDN, version, actor.Login),
			Details: jsonDetails(map[string]any{
				"version": version, "fingerprint": cert.FingerprintSHA256, "reason": reason, "actor": actor.Login,
			}),
		}); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "certificate.rollback", "domain", d.ID.String(),
			map[string]any{"version": version, "fingerprint": cert.FingerprintSHA256, "reason": reason})
	})
	if err != nil {
		return nil, fmt.Errorf("rollback: %w", err)
	}
	s.linkCurrent(d.FQDN, cert.FingerprintSHA256)
	return dc, nil
}

// certVisible reports whether actor can read a certificate, i.e. it belongs to
// the history of at least one domain they can read.
func (s *Services) certVisible(ctx context.Context, actor *domain.User, certID uuid.UUID) (bool, error) {
	if isAdmin(actor) {
		return true, nil
	}
	ids, err := s.Authz.VisibleDomainIDs(ctx, actor)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		dcs, err := s.Store.ListDomainCertificates(ctx, id)
		if err != nil {
			return false, err
		}
		for _, dc := range dcs {
			if dc.CertificateID == certID {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetCertificate returns certificate metadata by fingerprint.
func (s *Services) GetCertificate(ctx context.Context, actor *domain.User, fingerprint string) (*domain.Certificate, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, invalidf("invalid fingerprint")
	}
	c, err := s.Store.GetCertificateByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("get certificate: %w", err)
	}
	ok, err := s.certVisible(ctx, actor, c.ID)
	if err != nil {
		return nil, fmt.Errorf("get certificate: %w", err)
	}
	if !ok {
		return nil, forbiddenf("certificate not accessible")
	}
	return c, nil
}

// DownloadCertificate returns a PEM file of a certificate: PartCert and
// PartChain for anyone who can read it, PartKey for admins only (audited).
func (s *Services) DownloadCertificate(ctx context.Context, actor *domain.User, fingerprint, part string) ([]byte, error) {
	var file string
	switch part {
	case PartCert:
		file = certFileName
	case PartChain:
		file = chainFileName
	case PartKey:
		if err := requireAdmin(actor); err != nil {
			return nil, err
		}
		file = keyFileName
	default:
		return nil, invalidf("unknown certificate part")
	}
	c, err := s.GetCertificate(ctx, actor, fingerprint)
	if err != nil {
		return nil, err
	}
	b, err := s.readCertFile(c.FingerprintSHA256, file)
	if err != nil {
		return nil, err
	}
	if part == PartKey {
		if err := s.audit(ctx, s.Store, actor, "certificate.key_download", "certificate", c.ID.String(),
			map[string]any{"fingerprint": c.FingerprintSHA256}); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// DeleteCertificate removes a certificate that is not current for any domain,
// then its files. Admin only.
func (s *Services) DeleteCertificate(ctx context.Context, actor *domain.User, fingerprint string) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	if !ValidFingerprint(fingerprint) {
		return invalidf("invalid fingerprint")
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		c, err := tx.GetCertificateByFingerprint(ctx, fingerprint)
		if err != nil {
			return err
		}
		inUse, err := tx.CertificateInUse(ctx, c.ID)
		if err != nil {
			return err
		}
		if inUse {
			return domain.ErrCertificateInUse
		}
		if err := tx.DeleteCertificate(ctx, c.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "certificate.delete", "certificate", c.ID.String(),
			map[string]any{"fingerprint": fingerprint})
	})
	if err != nil {
		return fmt.Errorf("delete certificate: %w", err)
	}
	if err := s.removeCertFiles(fingerprint); err != nil {
		s.log().Warn("remove certificate files failed", "component", "service", "operation", "delete_certificate",
			"fingerprint", fingerprint, "error", err)
	}
	return nil
}
