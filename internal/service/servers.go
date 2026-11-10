package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/agentcfg"
	"github.com/kogonia/tlsherd/internal/domain"
	"github.com/kogonia/tlsherd/internal/store"
)

// ServerView is a server with list-friendly extras.
type ServerView struct {
	domain.Server
	Label     string      `json:"label"` // display_name or IP
	KeyPrefix string      `json:"key_prefix,omitempty"`
	DomainIDs []uuid.UUID `json:"domain_ids"`
	// Problems summarizes open alarms for the list/detail pages.
	OpenEvents         int      `json:"open_events"`
	OpenCritical       int      `json:"open_critical"`
	OpenWarning        int      `json:"open_warning"`
	OpenEventTypes     []string `json:"open_event_types,omitempty"`
	MaxEventSeverity   string   `json:"max_event_severity,omitempty"`
	EndpointsUnhealthy int      `json:"endpoints_unhealthy"`
}

// EffectiveConfig is the agent configuration a server actually runs with.
type EffectiveConfig struct {
	Config     agentcfg.Config `json:"config"`
	Version    int64           `json:"config_version"`
	Hash       string          `json:"config_hash"`
	UsesCustom bool            `json:"uses_custom_config"`
}

// ServerConfigInput controls UpdateServerConfig.
type ServerConfigInput struct {
	// Config is the new per-server document (ignored with ForceFromDefaults).
	Config json.RawMessage
	// Confirm must be true: replacing a server's config is always explicit.
	Confirm bool
	// ForceFromDefaults replaces the server's config with a copy of the current defaults.
	ForceFromDefaults bool
}

// AgentDefaultsView is the global default agent configuration.
type AgentDefaultsView struct {
	Config    agentcfg.Config `json:"config"`
	Version   int64           `json:"config_version"`
	Hash      string          `json:"config_hash"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// DomainServerInput describes a domain->server assignment.
type DomainServerInput struct {
	InstallMode     string
	CertPath        string
	KeyPath         string
	ChainPath       string
	FullchainPath   string
	RestartOverride json.RawMessage
}

// RotateResult is returned by RotateAgentKey. APIKey is shown once.
type RotateResult struct {
	APIKey          string    `json:"api_key"`
	KeyPrefix       string    `json:"key_prefix"`
	OldKeysExpireAt time.Time `json:"old_keys_expire_at"`
}

// ---------------------------------------------------------------------------
// Servers

func (s *Services) serverView(ctx context.Context, sv domain.Server) (*ServerView, error) {
	v := &ServerView{Server: sv, Label: sv.Display(), DomainIDs: []uuid.UUID{}}
	if p, err := s.Store.ActiveKeyPrefix(ctx, sv.ID); err == nil {
		v.KeyPrefix = p
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	dss, err := s.Store.ListDomainServersByServer(ctx, sv.ID)
	if err != nil {
		return nil, err
	}
	for _, ds := range dss {
		v.DomainIDs = append(v.DomainIDs, ds.DomainID)
	}
	return v, nil
}

// ListServers returns the servers visible to actor: all for admins, only
// servers assigned to a readable domain for operators.
func (s *Services) ListServers(ctx context.Context, actor *domain.User) ([]ServerView, error) {
	all, err := s.Store.ListServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	openByServer, err := s.Store.CountOpenEventsByServer(ctx)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	unhealthyByServer, err := s.Store.CountUnhealthyEndpointsByServer(ctx)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	var visible map[uuid.UUID]struct{}
	if !isAdmin(actor) {
		ids, err := s.Authz.VisibleDomainIDs(ctx, actor)
		if err != nil {
			return nil, fmt.Errorf("list servers: %w", err)
		}
		visible = make(map[uuid.UUID]struct{}, len(ids))
		for _, id := range ids {
			visible[id] = struct{}{}
		}
	}
	out := make([]ServerView, 0, len(all))
	for _, sv := range all {
		v, err := s.serverView(ctx, sv)
		if err != nil {
			return nil, fmt.Errorf("list servers: %w", err)
		}
		if c, ok := openByServer[sv.ID]; ok {
			v.OpenEvents = c.Total
			v.OpenCritical = c.Critical
			v.OpenWarning = c.Warning
			v.OpenEventTypes = c.Types
			v.MaxEventSeverity = c.MaxSeverity
		}
		v.EndpointsUnhealthy = unhealthyByServer[sv.ID]
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

// GetServer returns one server. Operators need a readable assigned domain.
func (s *Services) GetServer(ctx context.Context, actor *domain.User, id uuid.UUID) (*ServerView, error) {
	if err := s.requireServerRead(ctx, actor, id); err != nil {
		return nil, err
	}
	sv, err := s.Store.GetServer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}
	v, err := s.serverView(ctx, *sv)
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}
	if openByServer, err := s.Store.CountOpenEventsByServer(ctx); err == nil {
		if c, ok := openByServer[id]; ok {
			v.OpenEvents = c.Total
			v.OpenCritical = c.Critical
			v.OpenWarning = c.Warning
			v.OpenEventTypes = c.Types
			v.MaxEventSeverity = c.MaxSeverity
		}
	} else {
		return nil, fmt.Errorf("get server: %w", err)
	}
	if unhealthy, err := s.Store.CountUnhealthyEndpointsByServer(ctx); err == nil {
		v.EndpointsUnhealthy = unhealthy[id]
	} else {
		return nil, fmt.Errorf("get server: %w", err)
	}
	return v, nil
}

// UpdateServer changes the display name (empty clears it). Requires server write access.
func (s *Services) UpdateServer(ctx context.Context, actor *domain.User, id uuid.UUID, displayName *string) (*ServerView, error) {
	if err := s.requireServerWrite(ctx, actor, id); err != nil {
		return nil, err
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		sv, err := tx.GetServer(ctx, id)
		if err != nil {
			return err
		}
		if displayName != nil {
			if n := truncate(normalizeText(*displayName), 128); n != "" {
				sv.DisplayName = &n
			} else {
				sv.DisplayName = nil
			}
		}
		if err := tx.UpdateServer(ctx, sv); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "server.update", "server", id.String(),
			map[string]any{"display_name": sv.DisplayName})
	})
	if err != nil {
		return nil, fmt.Errorf("update server: %w", err)
	}
	return s.GetServer(ctx, actor, id)
}

// DeleteServer removes a server. Its keys stop working immediately; the agent
// falls back to enrollment and re-queues with reason re_enroll_after_delete. Admin only.
func (s *Services) DeleteServer(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		sv, err := tx.GetServer(ctx, id)
		if err != nil {
			return err
		}
		if err := tx.DeleteServer(ctx, id); err != nil {
			return err
		}
		if err := s.clearDelivery(ctx, tx, id); err != nil {
			return err
		}
		if sv.LastIP != nil {
			marker := jsonDetails(map[string]any{"server_id": id, "deleted_at": s.now()})
			if err := tx.SetSetting(ctx, settingDeletedIP+sv.LastIP.String(), marker); err != nil {
				return err
			}
		}
		for _, t := range []string{EvAgentOffline, EvAgentIdentityMismatch} {
			if err := s.resolve(ctx, tx, DedupKey(t, id.String()), "server_deleted"); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, actor, "server.delete", "server", id.String(),
			map[string]any{"label": sv.Display(), "ip": ipPtrString(sv.LastIP)})
	})
	if err != nil {
		return fmt.Errorf("delete server: %w", err)
	}
	return nil
}

// RotateAgentKey issues a new key and lets the old keys live for another 24h.
// The new key reaches the agent through its next poll response; it is also
// returned here once. Admin only.
func (s *Services) RotateAgentKey(ctx context.Context, actor *domain.User, id uuid.UUID) (*RotateResult, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	var res *RotateResult
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if _, err := tx.GetServer(ctx, id); err != nil {
			return err
		}
		now := s.now()
		until := now.Add(KeyRotationOverlap)
		keys, err := tx.ListAgentKeys(ctx, id)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.RevokedAt != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(until)) {
				continue
			}
			if err := tx.SetAgentKeyExpiry(ctx, k.ID, until); err != nil {
				return err
			}
		}
		plain, key, err := s.issueAgentKey(ctx, tx, id, "rotated")
		if err != nil {
			return err
		}
		if err := s.putDelivery(ctx, tx, id, key.ID, plain); err != nil {
			return err
		}
		res = &RotateResult{APIKey: plain, KeyPrefix: key.KeyPrefix, OldKeysExpireAt: until}
		return s.audit(ctx, tx, actor, "server.rotate_key", "server", id.String(),
			map[string]any{"key_prefix": key.KeyPrefix, "old_keys_expire_at": until})
	})
	if err != nil {
		return nil, fmt.Errorf("rotate agent key: %w", err)
	}
	return res, nil
}

// RevokeServerKeys revokes all keys of a server immediately (agent gets 401
// and re-enrolls). Admin only.
func (s *Services) RevokeServerKeys(ctx context.Context, actor *domain.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if _, err := tx.GetServer(ctx, id); err != nil {
			return err
		}
		if err := s.revokeAllKeys(ctx, tx, id, s.now()); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "server.revoke_keys", "server", id.String(), nil)
	})
	if err != nil {
		return fmt.Errorf("revoke server keys: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Agent configuration

// effectiveConfig resolves the configuration of a server without authz checks.
// A per-server document replaces the defaults entirely.
func (s *Services) effectiveConfig(ctx context.Context, srv *domain.Server) (*EffectiveConfig, error) {
	sc, err := s.Store.GetServerConfig(ctx, srv.ID)
	var (
		raw     []byte
		version int64
		custom  bool
	)
	switch {
	case err == nil:
		raw, version, custom = sc.Config, sc.ConfigVersion, true
	case errors.Is(err, domain.ErrNotFound):
		d, derr := s.Store.GetAgentDefaults(ctx)
		if derr != nil {
			return nil, fmt.Errorf("effective config: %w", derr)
		}
		raw, version = d.Config, d.ConfigVersion
	default:
		return nil, fmt.Errorf("effective config: %w", err)
	}
	cfg, err := agentcfg.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("effective config: stored document is invalid: %w", err)
	}
	h, err := agentcfg.Hash(cfg)
	if err != nil {
		return nil, fmt.Errorf("effective config: %w", err)
	}
	s.log().Debug("resolved effective agent config",
		"component", "service", "operation", "effective_config",
		"server_id", srv.ID, "version", version, "hash", h, "uses_custom", custom,
		"poll_interval", cfg.PollInterval.Std().String(),
		"enroll_interval", cfg.EnrollInterval.Std().String())
	return &EffectiveConfig{Config: cfg, Version: version, Hash: h, UsesCustom: custom}, nil
}

// GetEffectiveConfig returns the configuration a server runs with. Requires server read access.
func (s *Services) GetEffectiveConfig(ctx context.Context, actor *domain.User, serverID uuid.UUID) (*EffectiveConfig, error) {
	if err := s.requireServerRead(ctx, actor, serverID); err != nil {
		return nil, err
	}
	srv, err := s.Store.GetServer(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("get effective config: %w", err)
	}
	return s.effectiveConfig(ctx, srv)
}

func parseConfigDoc(doc []byte) (agentcfg.Config, []byte, error) {
	cfg, err := agentcfg.Parse(doc)
	if err != nil {
		return agentcfg.Config{}, nil, invalidf("invalid agent config: %s", err.Error())
	}
	canonical, err := agentcfg.CanonicalJSON(cfg)
	if err != nil {
		return agentcfg.Config{}, nil, fmt.Errorf("encode agent config: %w", err)
	}
	return cfg, canonical, nil
}

// GetAgentDefaults returns the global defaults. Admin only.
func (s *Services) GetAgentDefaults(ctx context.Context, actor *domain.User) (*AgentDefaultsView, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	d, err := s.Store.GetAgentDefaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("get agent defaults: %w", err)
	}
	return defaultsView(d)
}

func defaultsView(d *domain.AgentDefaults) (*AgentDefaultsView, error) {
	cfg, err := agentcfg.Parse(d.Config)
	if err != nil {
		return nil, fmt.Errorf("stored agent defaults are invalid: %w", err)
	}
	h, err := agentcfg.Hash(cfg)
	if err != nil {
		return nil, err
	}
	return &AgentDefaultsView{Config: cfg, Version: d.ConfigVersion, Hash: h, UpdatedAt: d.UpdatedAt}, nil
}

// UpdateAgentDefaults replaces the global defaults. Servers with their own
// config are unaffected. Admin only.
func (s *Services) UpdateAgentDefaults(ctx context.Context, actor *domain.User, doc json.RawMessage) (*AgentDefaultsView, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	_, canonical, err := parseConfigDoc(doc)
	if err != nil {
		return nil, err
	}
	var out *AgentDefaultsView
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		cur, err := tx.GetAgentDefaults(ctx)
		if err != nil {
			return err
		}
		version := cur.ConfigVersion + 1
		if err := tx.UpdateAgentDefaults(ctx, canonical, version); err != nil {
			return err
		}
		servers, err := tx.ListServers(ctx)
		if err != nil {
			return err
		}
		for i := range servers {
			if servers[i].UsesCustomConfig || servers[i].ConfigVersion == version {
				continue
			}
			servers[i].ConfigVersion = version
			if err := tx.UpdateServer(ctx, &servers[i]); err != nil {
				return err
			}
		}
		nd, err := tx.GetAgentDefaults(ctx)
		if err != nil {
			return err
		}
		if out, err = defaultsView(nd); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, &domain.Event{
			Type: EvAgentConfigUpdated, Severity: SeverityInfo, ActorUserID: actorID(actor),
			Message: fmt.Sprintf("agent defaults updated to version %d by %s", version, actor.Login),
			Details: jsonDetails(map[string]any{"scope": "defaults", "version": version}),
		}); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "agent_defaults.update", "settings", "agent-defaults",
			map[string]any{"version": version})
	})
	if err != nil {
		return nil, fmt.Errorf("update agent defaults: %w", err)
	}
	return out, nil
}

// UpdateServerConfig replaces the per-server agent config. Confirmation is
// mandatory. With ForceFromDefaults the document is a copy of the current
// defaults. Requires server write access.
func (s *Services) UpdateServerConfig(ctx context.Context, actor *domain.User, serverID uuid.UUID, in ServerConfigInput) (*EffectiveConfig, error) {
	if !in.Confirm {
		return nil, domain.ErrConfirmRequired
	}
	if err := s.requireServerWrite(ctx, actor, serverID); err != nil {
		return nil, err
	}
	if !in.ForceFromDefaults && len(in.Config) == 0 {
		return nil, invalidf("config is required")
	}
	var out *EffectiveConfig
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		srv, err := tx.GetServer(ctx, serverID)
		if err != nil {
			return err
		}
		defaults, err := tx.GetAgentDefaults(ctx)
		if err != nil {
			return err
		}
		doc := []byte(in.Config)
		if in.ForceFromDefaults {
			doc = defaults.Config
		}
		_, canonical, err := parseConfigDoc(doc)
		if err != nil {
			return err
		}
		// Versions only move forward so agents never see a "smaller" version
		// after switching between defaults and a custom document.
		version := max(srv.ConfigVersion, defaults.ConfigVersion)
		if prev, err := tx.GetServerConfig(ctx, serverID); err == nil {
			version = max(version, prev.ConfigVersion)
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		version++
		sc := &domain.ServerConfig{ServerID: serverID, Config: canonical, ConfigVersion: version}
		if err := tx.UpsertServerConfig(ctx, sc); err != nil {
			return err
		}
		srv.UsesCustomConfig, srv.ConfigVersion = true, sc.ConfigVersion
		if err := tx.UpdateServer(ctx, srv); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, &domain.Event{
			Type: EvAgentConfigUpdated, Severity: SeverityInfo, ServerID: &serverID, ActorUserID: actorID(actor),
			Message: fmt.Sprintf("agent config of %s updated to version %d by %s", srv.Display(), sc.ConfigVersion, actor.Login),
			Details: jsonDetails(map[string]any{"scope": "server", "version": sc.ConfigVersion, "from_defaults": in.ForceFromDefaults}),
		}); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, actor, "server.config_update", "server", serverID.String(),
			map[string]any{"version": sc.ConfigVersion, "from_defaults": in.ForceFromDefaults}); err != nil {
			return err
		}
		parsed, err := agentcfg.Parse(canonical)
		if err != nil {
			return err
		}
		h, err := agentcfg.Hash(parsed)
		if err != nil {
			return err
		}
		out = &EffectiveConfig{Config: parsed, Version: sc.ConfigVersion, Hash: h, UsesCustom: true}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("update server config: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Domain <-> server assignment

func validateAssignmentPath(label, p string) error {
	if strings.ContainsRune(p, 0) {
		return invalidf("%s contains a NUL byte", label)
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return invalidf("%s must not contain '..'", label)
		}
	}
	return nil
}

// validateInstallAssignment validates the install mode, target paths and
// restart override shared by domain and managed-certificate server
// assignments. It returns the restart override to store (nil when unset).
func validateInstallAssignment(mode string, paths map[string]string, restart json.RawMessage) (json.RawMessage, error) {
	switch mode {
	case "", "symlink", "copy":
	default:
		return nil, invalidf("install_mode must be symlink or copy")
	}
	for label, p := range paths {
		if err := validateAssignmentPath(label, p); err != nil {
			return nil, err
		}
	}
	if len(restart) == 0 || string(restart) == "null" {
		return nil, nil
	}
	var r agentcfg.Restart
	if err := json.Unmarshal(restart, &r); err != nil {
		return nil, invalidf("restart_override: %s", err.Error())
	}
	check := agentcfg.Default()
	check.Restart = r
	if err := agentcfg.Validate(check); err != nil {
		return nil, invalidf("restart_override: %s", err.Error())
	}
	return restart, nil
}

// ListDomainServers lists the servers assigned to a domain. Requires can_read on the domain.
func (s *Services) ListDomainServers(ctx context.Context, actor *domain.User, domainID uuid.UUID) ([]domain.DomainServer, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permRead); err != nil {
		return nil, err
	}
	out, err := s.Store.ListDomainServersByDomain(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("list domain servers: %w", err)
	}
	return out, nil
}

// UpsertDomainServer creates or updates an assignment. Requires
// can_write_config on the domain; creating a new assignment (which grants
// config access to the server) is admin only.
func (s *Services) UpsertDomainServer(ctx context.Context, actor *domain.User, domainID, serverID uuid.UUID, in DomainServerInput) (*domain.DomainServer, error) {
	if err := s.requireDomainPerm(ctx, actor, domainID, permWriteConfig); err != nil {
		return nil, err
	}
	var err error
	in.RestartOverride, err = validateInstallAssignment(in.InstallMode, map[string]string{
		"cert_path": in.CertPath, "key_path": in.KeyPath,
		"chain_path": in.ChainPath, "fullchain_path": in.FullchainPath,
	}, in.RestartOverride)
	if err != nil {
		return nil, err
	}
	ds := &domain.DomainServer{
		DomainID: domainID, ServerID: serverID, InstallMode: in.InstallMode,
		CertPath: in.CertPath, KeyPath: in.KeyPath, ChainPath: in.ChainPath,
		FullchainPath: in.FullchainPath, RestartOverride: in.RestartOverride,
	}
	err = s.Store.Tx(ctx, func(tx store.Store) error {
		if _, err := tx.GetDomain(ctx, domainID); err != nil {
			return err
		}
		srv, err := tx.GetServer(ctx, serverID)
		if err != nil {
			return err
		}
		existing, err := tx.ListDomainServersByDomain(ctx, domainID)
		if err != nil {
			return err
		}
		linked := false
		for _, e := range existing {
			linked = linked || e.ServerID == serverID
		}
		if !linked {
			if err := requireAdmin(actor); err != nil {
				return err
			}
		}
		if err := tx.UpsertDomainServer(ctx, ds); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "domain_server.upsert", "domain", domainID.String(), map[string]any{
			"server_id": serverID, "server": srv.Display(), "install_mode": ds.InstallMode, "created": !linked,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("upsert domain server: %w", err)
	}
	return ds, nil
}

// RemoveDomainServer removes an assignment. Requires can_write_config on the
// domain. Files already installed on the host are left in place by the agent.
func (s *Services) RemoveDomainServer(ctx context.Context, actor *domain.User, domainID, serverID uuid.UUID) error {
	if err := s.requireDomainPerm(ctx, actor, domainID, permWriteConfig); err != nil {
		return err
	}
	err := s.Store.Tx(ctx, func(tx store.Store) error {
		if err := tx.DeleteDomainServer(ctx, domainID, serverID); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "domain_server.remove", "domain", domainID.String(),
			map[string]any{"server_id": serverID})
	})
	if err != nil {
		return fmt.Errorf("remove domain server: %w", err)
	}
	return nil
}
