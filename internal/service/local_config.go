package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/domain"
)

// LocalConfigUpdate is pushed to the agent via enroll/poll when an admin edit is pending.
type LocalConfigUpdate struct {
	Config   agentcfg.LocalConfig `json:"config"`
	BaseHash string               `json:"base_hash,omitempty"`
	Revision int64                `json:"revision,omitempty"`
}

// ServerLocalConfigView is the admin view of an agent's local config.
type ServerLocalConfigView struct {
	Reported          *agentcfg.LocalConfig `json:"reported,omitempty"`
	ReportedHash      string                `json:"reported_hash,omitempty"`
	ReportedUpdatedAt *time.Time            `json:"reported_updated_at,omitempty"`
	Pending           *agentcfg.LocalConfig `json:"pending,omitempty"`
	PendingBaseHash   string                `json:"pending_base_hash,omitempty"`
	PendingRevision   int64                 `json:"pending_revision,omitempty"`
	Conflict          bool                  `json:"conflict"`
	Services          []ServiceCatalogEntry `json:"services"`
}

// ServiceCatalogEntry is exposed to the UI (web recipe + systemd preset).
type ServiceCatalogEntry struct {
	ID            string             `json:"id"`
	Label         string             `json:"label"`
	DefaultName   string             `json:"default_name"`
	VerifyCommand []string           `json:"verify_command"`
	ReloadCommand []string           `json:"reload_command"`
	Verify        agentcfg.Verify    `json:"verify"`  // systemd preset
	Restart       agentcfg.Restart   `json:"restart"` // systemd preset
}

// SetLocalConfigInput is an admin edit of the agent's local config.
type SetLocalConfigInput struct {
	Config      *agentcfg.LocalConfig `json:"config"`
	ResetFields []string              `json:"reset_fields,omitempty"`
	ResetAll    bool                  `json:"reset_all"`
	Service     string                `json:"service,omitempty"` // when resetting / changing catalog id
	Confirm     bool                  `json:"confirm"`
}

func catalogEntries() []ServiceCatalogEntry {
	out := make([]ServiceCatalogEntry, 0, len(agentcfg.Services()))
	for _, s := range agentcfg.Services() {
		out = append(out, ServiceCatalogEntry{
			ID: s.ID, Label: s.Label, DefaultName: s.DefaultName,
			VerifyCommand: append([]string(nil), s.VerifyCommand...),
			ReloadCommand: append([]string(nil), s.ReloadCommand...),
			Verify:        s.Verify,
			Restart:       s.Restart,
		})
	}
	return out
}

// ListAgentServices returns the built-in service catalog for the UI.
func ListAgentServices() []ServiceCatalogEntry { return catalogEntries() }

// ReportAgentLocalConfig stores the agent's reported local config and clears
// pending when the reported hash matches the pending document.
func (s *Services) ReportAgentLocalConfig(ctx context.Context, srv *domain.Server, lc agentcfg.LocalConfig, hash string, conflict bool) error {
	if srv == nil {
		return nil
	}
	if hash == "" {
		var err error
		hash, err = agentcfg.HashLocal(lc)
		if err != nil {
			return fmt.Errorf("hash local config: %w", err)
		}
	}
	if err := agentcfg.ValidateLocal(lc); err != nil {
		return invalidf("local_config: %s", err.Error())
	}
	raw, err := agentcfg.CanonicalLocalJSON(lc)
	if err != nil {
		return err
	}
	cur, err := s.Store.GetServer(ctx, srv.ID)
	if err != nil {
		return err
	}
	now := s.now()
	cur.AgentLocalConfig = raw
	cur.AgentLocalConfigHash = hash
	cur.AgentLocalConfigUpdatedAt = &now
	cur.LocalConfigConflict = conflict

	if len(cur.PendingLocalConfig) > 0 {
		pendingHash, err := hashPending(cur.PendingLocalConfig)
		if err == nil && pendingHash == hash {
			cur.PendingLocalConfig = nil
			cur.PendingLocalConfigBaseHash = ""
			cur.LocalConfigConflict = false
			s.log().Info("pending local config applied by agent",
				"component", "service", "operation", "local_config_ack",
				"server_id", cur.ID, "revision", cur.PendingLocalConfigRevision, "hash", hash)
		}
	}
	if err := s.Store.UpdateServer(ctx, cur); err != nil {
		return fmt.Errorf("store agent local config: %w", err)
	}
	*srv = *cur
	return nil
}

func hashPending(raw []byte) (string, error) {
	lc, err := agentcfg.ParseLocal(raw)
	if err != nil {
		return "", err
	}
	return agentcfg.HashLocal(lc)
}

// pendingLocalConfigUpdate builds a push payload if the server has a pending edit.
func pendingLocalConfigUpdate(srv *domain.Server) *LocalConfigUpdate {
	if srv == nil || len(srv.PendingLocalConfig) == 0 {
		return nil
	}
	lc, err := agentcfg.ParseLocal(srv.PendingLocalConfig)
	if err != nil {
		return nil
	}
	return &LocalConfigUpdate{
		Config:   lc,
		BaseHash: srv.PendingLocalConfigBaseHash,
		Revision: srv.PendingLocalConfigRevision,
	}
}

// GetServerLocalConfig returns reported + pending local config for admins/operators with read access.
func (s *Services) GetServerLocalConfig(ctx context.Context, actor *domain.User, serverID uuid.UUID) (*ServerLocalConfigView, error) {
	srv, err := s.GetServer(ctx, actor, serverID)
	if err != nil {
		return nil, err
	}
	view := &ServerLocalConfigView{
		ReportedHash:      srv.AgentLocalConfigHash,
		ReportedUpdatedAt: srv.AgentLocalConfigUpdatedAt,
		PendingBaseHash:   srv.PendingLocalConfigBaseHash,
		PendingRevision:   srv.PendingLocalConfigRevision,
		Conflict:          srv.LocalConfigConflict,
		Services:          catalogEntries(),
	}
	if len(srv.AgentLocalConfig) > 0 {
		lc, err := agentcfg.ParseLocal(srv.AgentLocalConfig)
		if err != nil {
			return nil, fmt.Errorf("parse reported local config: %w", err)
		}
		view.Reported = &lc
	}
	if len(srv.PendingLocalConfig) > 0 {
		lc, err := agentcfg.ParseLocal(srv.PendingLocalConfig)
		if err != nil {
			return nil, fmt.Errorf("parse pending local config: %w", err)
		}
		view.Pending = &lc
	}
	return view, nil
}

// SetServerLocalConfig queues a pending local-config push for the agent.
func (s *Services) SetServerLocalConfig(ctx context.Context, actor *domain.User, serverID uuid.UUID, in SetLocalConfigInput) (*ServerLocalConfigView, error) {
	if !in.Confirm {
		return nil, domain.ErrConfirmRequired
	}
	if err := s.requireServerWrite(ctx, actor, serverID); err != nil {
		return nil, err
	}
	srv, err := s.Store.GetServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	base := agentcfg.DefaultLocal()
	if len(srv.AgentLocalConfig) > 0 {
		if parsed, err := agentcfg.ParseLocal(srv.AgentLocalConfig); err == nil {
			base = parsed
		}
	}
	if len(srv.PendingLocalConfig) > 0 {
		if parsed, err := agentcfg.ParseLocal(srv.PendingLocalConfig); err == nil {
			base = parsed
		}
	}

	out := base
	if in.ResetAll {
		svcID := in.Service
		if svcID == "" {
			svcID = out.Service
		}
		out, err = agentcfg.ApplyServiceDefaults(out, svcID)
		if err != nil {
			return nil, invalidf("%s", err.Error())
		}
	} else {
		if in.Service != "" && in.Service != out.Service {
			out, err = agentcfg.ApplyServiceDefaults(out, in.Service)
			if err != nil {
				return nil, invalidf("%s", err.Error())
			}
		}
		if in.Config != nil {
			out = agentcfg.MergeLocal(out, *in.Config)
			if in.Config.Service != "" {
				out.Service = in.Config.Service
			}
		}
		for _, f := range in.ResetFields {
			out, err = resetLocalField(out, f)
			if err != nil {
				return nil, invalidf("%s", err.Error())
			}
		}
	}
	if err := agentcfg.ValidateLocal(out); err != nil {
		return nil, invalidf("local_config: %s", err.Error())
	}
	raw, err := agentcfg.CanonicalLocalJSON(out)
	if err != nil {
		return nil, err
	}
	srv.PendingLocalConfig = raw
	srv.PendingLocalConfigBaseHash = srv.AgentLocalConfigHash
	srv.PendingLocalConfigRevision++
	srv.LocalConfigConflict = false
	if err := s.Store.UpdateServer(ctx, srv); err != nil {
		return nil, err
	}
	_ = s.audit(ctx, s.Store, actor, "server.local_config_update", "server", serverID.String(),
		map[string]any{"revision": srv.PendingLocalConfigRevision, "base_hash": srv.PendingLocalConfigBaseHash, "service": out.Service})
	s.log().Info("queued agent local config update",
		"component", "service", "operation", "set_local_config",
		"server_id", serverID, "revision", srv.PendingLocalConfigRevision, "actor", actor.Login)

	return s.GetServerLocalConfig(ctx, actor, serverID)
}

func resetLocalField(lc agentcfg.LocalConfig, field string) (agentcfg.LocalConfig, error) {
	info, ok := agentcfg.ServiceByID(lc.Service)
	if !ok {
		info, _ = agentcfg.ServiceByID(agentcfg.ServiceCustom)
	}
	deploy := lc.Restart.Type
	if deploy == "" {
		deploy = agentcfg.DeploySystemd
	}
	v, r := info.Preset(deploy, lc.Restart.Name)
	switch field {
	case "verify", "verify.command", "verify.timeout":
		lc.Verify = v
	case "restart", "restart.type", "restart.name", "restart.reload_only", "restart.command":
		lc.Restart = r
	case "install":
		lc.Install = agentcfg.Default().Install
	case "cert_path":
		lc.CertPath = ""
	case "key_path":
		lc.KeyPath = ""
	case "chain_path":
		lc.ChainPath = ""
	case "fullchain_path":
		lc.FullchainPath = ""
	case "cert_root":
		lc.CertRoot = ""
	case "strict_cert_check":
		lc.StrictCertCheck = nil
	case "service":
		return agentcfg.ApplyServiceDefaults(lc, lc.Service)
	default:
		return lc, fmt.Errorf("unknown reset field %q", field)
	}
	return lc, nil
}
