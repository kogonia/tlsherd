package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// Apply result statuses accepted from agents.
const (
	ApplySuccess           = "success"
	ApplyStaged            = "staged"
	ApplyFailed            = "failed"
	ApplyVerifyFailed      = "verify_failed"
	ApplyPostCheckMismatch = "post_check_mismatch"
)

// PollDomain is one domain assigned to the polling server, with the
// certificate the agent should converge to.
type PollDomain struct {
	DomainID        uuid.UUID       `json:"domain_id"`
	FQDN            string          `json:"fqdn"`
	Version         int             `json:"version"`
	Fingerprint     string          `json:"fingerprint_sha256"`
	NotBefore       time.Time       `json:"not_before"`
	NotAfter        time.Time       `json:"not_after"`
	InstallMode     string          `json:"install_mode"`
	CertPath        string          `json:"cert_path"`
	KeyPath         string          `json:"key_path"`
	ChainPath       string          `json:"chain_path"`
	RestartOverride json.RawMessage `json:"restart_override,omitempty"`
}

// PollResponse is the server-authoritative state returned to an agent.
type PollResponse struct {
	ServerID      uuid.UUID       `json:"server_id"`
	ServerTime    time.Time       `json:"server_time"`
	ConfigVersion int64           `json:"config_version"`
	ConfigHash    string          `json:"config_hash"`
	Config        agentcfg.Config `json:"config"`
	Domains       []PollDomain    `json:"domains"`
	// NewAPIKey is set while a rotated key waits to be adopted by the agent.
	NewAPIKey string `json:"new_api_key,omitempty"`
	// LocalConfigUpdate is set when an admin-edited local config awaits apply.
	LocalConfigUpdate *LocalConfigUpdate `json:"local_config_update,omitempty"`
}

// AgentPollInput carries optional agent-reported local config.
type AgentPollInput struct {
	LocalConfig         *agentcfg.LocalConfig `json:"local_config,omitempty"`
	LocalConfigHash     string                `json:"local_config_hash,omitempty"`
	LocalConfigConflict bool                  `json:"local_config_conflict,omitempty"`
}

// CertBundle is the PEM material served to an assigned agent.
type CertBundle struct {
	Fingerprint string `json:"fingerprint_sha256"`
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	Chain       string `json:"chain"`
}

// ApplyResultInput is an agent's report about one apply attempt.
type ApplyResultInput struct {
	ApplyID     string          `json:"apply_id"`
	Domain      string          `json:"domain"`
	Fingerprint string          `json:"fingerprint_sha256"`
	Status      string          `json:"status"`
	Message     string          `json:"message"`
	Details     json.RawMessage `json:"details"`
}

// AgentPoll returns the effective config and the domain assignments of an
// authenticated server. Domains without a current certificate are omitted.
func (s *Services) AgentPoll(ctx context.Context, srv *domain.Server, in AgentPollInput) (*PollResponse, error) {
	if in.LocalConfig != nil {
		if err := s.ReportAgentLocalConfig(ctx, srv, *in.LocalConfig, in.LocalConfigHash, in.LocalConfigConflict); err != nil {
			return nil, err
		}
		// Reload server so pending clear / conflict flags are current for the response.
		fresh, err := s.Store.GetServer(ctx, srv.ID)
		if err != nil {
			return nil, err
		}
		*srv = *fresh
	}
	eff, err := s.effectiveConfig(ctx, srv)
	if err != nil {
		return nil, err
	}
	assignments, err := s.assignedCurrent(ctx, srv.ID)
	if err != nil {
		return nil, fmt.Errorf("agent poll: %w", err)
	}
	res := &PollResponse{
		ServerID: srv.ID, ServerTime: s.now(),
		ConfigVersion: eff.Version, ConfigHash: eff.Hash, Config: eff.Config,
		Domains: make([]PollDomain, 0, len(assignments)),
		LocalConfigUpdate: pendingLocalConfigUpdate(srv),
	}
	for _, a := range assignments {
		pd := PollDomain{
			DomainID: a.domain.ID, FQDN: a.domain.FQDN, Version: a.dc.Version,
			Fingerprint: a.cert.FingerprintSHA256, NotBefore: a.cert.NotBefore, NotAfter: a.cert.NotAfter,
			InstallMode: a.ds.InstallMode, CertPath: a.ds.CertPath, KeyPath: a.ds.KeyPath, ChainPath: a.ds.ChainPath,
		}
		if len(a.ds.RestartOverride) > 0 {
			pd.RestartOverride = json.RawMessage(a.ds.RestartOverride)
		}
		res.Domains = append(res.Domains, pd)
	}
	d, err := s.getDelivery(ctx, srv.ID)
	if err != nil {
		return nil, err
	}
	if d != nil {
		res.NewAPIKey = d.APIKey
	}
	s.log().Debug("agent poll",
		"component", "service", "operation", "agent_poll",
		"server_id", srv.ID, "config_version", res.ConfigVersion,
		"config_hash", res.ConfigHash, "domains", len(res.Domains),
		"has_new_api_key", res.NewAPIKey != "",
		"has_local_config_update", res.LocalConfigUpdate != nil)
	return res, nil
}

type assignment struct {
	ds     domain.DomainServer
	domain *domain.Domain
	dc     *domain.DomainCertificate
	cert   *domain.Certificate
}

// assignedCurrent lists the server's assigned domains that have a current certificate.
func (s *Services) assignedCurrent(ctx context.Context, serverID uuid.UUID) ([]assignment, error) {
	dss, err := s.Store.ListDomainServersByServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	out := make([]assignment, 0, len(dss))
	for _, ds := range dss {
		d, err := s.Store.GetDomain(ctx, ds.DomainID)
		if err != nil {
			return nil, err
		}
		dc, err := s.Store.GetCurrentDomainCertificate(ctx, ds.DomainID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return nil, err
		}
		c, err := s.Store.GetCertificate(ctx, dc.CertificateID)
		if err != nil {
			return nil, err
		}
		out = append(out, assignment{ds: ds, domain: d, dc: dc, cert: c})
	}
	return out, nil
}

// GetAgentCertBundle returns the PEM bundle with the given fingerprint, but
// only if it is the current certificate of a domain assigned to the server.
func (s *Services) GetAgentCertBundle(ctx context.Context, srv *domain.Server, fingerprint string) (*CertBundle, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, invalidf("invalid fingerprint")
	}
	assignments, err := s.assignedCurrent(ctx, srv.ID)
	if err != nil {
		return nil, fmt.Errorf("agent cert bundle: %w", err)
	}
	assigned := false
	for _, a := range assignments {
		if a.cert.FingerprintSHA256 == fingerprint {
			assigned = true
			break
		}
	}
	if !assigned {
		return nil, notFoundf("certificate is not assigned to this server")
	}
	b := &CertBundle{Fingerprint: fingerprint}
	for _, f := range []struct {
		name string
		dst  *string
	}{{certFileName, &b.Cert}, {keyFileName, &b.Key}, {chainFileName, &b.Chain}} {
		data, err := s.readCertFile(fingerprint, f.name)
		if err != nil {
			return nil, err
		}
		*f.dst = string(data)
	}
	return b, nil
}

// ReportApplyResult records the outcome of an apply and raises or resolves
// the corresponding events. Reports are idempotent per apply_id.
func (s *Services) ReportApplyResult(ctx context.Context, srv *domain.Server, in ApplyResultInput) error {
	in.ApplyID = normalizeText(in.ApplyID)
	if in.ApplyID == "" || len(in.ApplyID) > 128 {
		return invalidf("apply_id must be 1-128 characters")
	}
	switch in.Status {
	case ApplySuccess, ApplyStaged, ApplyFailed, ApplyVerifyFailed, ApplyPostCheckMismatch:
	default:
		return invalidf("unknown status %q", in.Status)
	}
	in.Message = truncate(in.Message, 2048)

	dss, err := s.Store.ListDomainServersByServer(ctx, srv.ID)
	if err != nil {
		return fmt.Errorf("report apply result: %w", err)
	}
	var dom *domain.Domain
	if in.Domain != "" {
		fqdn, err := NormalizeFQDN(in.Domain)
		if err != nil {
			return err
		}
		for _, ds := range dss {
			d, err := s.Store.GetDomain(ctx, ds.DomainID)
			if err != nil {
				return fmt.Errorf("report apply result: %w", err)
			}
			if d.FQDN == fqdn {
				dom = d
				break
			}
		}
		if dom == nil {
			return notFoundf("domain is not assigned to this server")
		}
	}
	details := []byte(in.Details)
	if len(details) > 0 && !json.Valid(details) {
		return invalidf("details must be valid JSON")
	}

	err = s.Store.Tx(ctx, func(tx store.Store) error {
		var domID *uuid.UUID
		entity := srv.ID.String()
		if dom != nil {
			domID = &dom.ID
			entity += ":" + dom.ID.String()
		}
		if err := tx.SaveApplyResult(ctx, in.ApplyID, srv.ID, domID, in.Status, in.Message, details); err != nil {
			return err
		}
		failureTypes := map[string]string{ // event type -> severity
			EvAgentApplyFailed:       SeverityCritical,
			EvAgentVerifyFailed:      SeverityCritical,
			EvAgentPostCheckMismatch: SeverityWarning,
		}
		var raise string
		switch in.Status {
		case ApplyFailed:
			raise = EvAgentApplyFailed
		case ApplyVerifyFailed:
			raise = EvAgentVerifyFailed
		case ApplyPostCheckMismatch:
			raise = EvAgentPostCheckMismatch
		case ApplySuccess:
			for t := range failureTypes {
				if err := s.resolve(ctx, tx, DedupKey(t, entity), "agent"); err != nil {
					return err
				}
			}
		}
		if raise == "" {
			return nil
		}
		key := DedupKey(raise, entity)
		return s.emit(ctx, tx, &domain.Event{
			Type: raise, Severity: failureTypes[raise], DomainID: domID, ServerID: &srv.ID, DedupKey: &key,
			Message: fmt.Sprintf("%s on %s: %s", raise, srv.Display(), in.Message),
			Details: jsonDetails(map[string]any{
				"apply_id": in.ApplyID, "fingerprint": in.Fingerprint, "status": in.Status, "message": in.Message,
			}),
		})
	})
	if err != nil {
		return fmt.Errorf("report apply result: %w", err)
	}
	return nil
}
