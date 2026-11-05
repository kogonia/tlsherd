package postgres

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kogonia/tlsherd/internal/domain"
)

// Servers

const serverCols = `id, display_name, last_ip, last_seen_at, agent_status, uses_custom_config,
	config_version, agent_local_config, agent_local_config_hash, agent_local_config_updated_at,
	pending_local_config, pending_local_config_base_hash, pending_local_config_revision,
	local_config_conflict, created_at`

func scanServer(r rowScanner) (domain.Server, error) {
	var sv domain.Server
	err := r.Scan(&sv.ID, &sv.DisplayName, &sv.LastIP, &sv.LastSeenAt, &sv.AgentStatus,
		&sv.UsesCustomConfig, &sv.ConfigVersion,
		&sv.AgentLocalConfig, &sv.AgentLocalConfigHash, &sv.AgentLocalConfigUpdatedAt,
		&sv.PendingLocalConfig, &sv.PendingLocalConfigBaseHash, &sv.PendingLocalConfigRevision,
		&sv.LocalConfigConflict, &sv.CreatedAt)
	return sv, err
}

// CreateServer inserts sv. An empty AgentStatus defaults to domain.ServerActive.
func (s *Store) CreateServer(ctx context.Context, sv *domain.Server) error {
	sv.ID = newID(sv.ID)
	if sv.AgentStatus == "" {
		sv.AgentStatus = domain.ServerActive
	}
	err := s.q.QueryRow(ctx, `
		INSERT INTO servers (id, display_name, last_ip, last_seen_at, agent_status,
			uses_custom_config, config_version,
			agent_local_config, agent_local_config_hash, agent_local_config_updated_at,
			pending_local_config, pending_local_config_base_hash, pending_local_config_revision,
			local_config_conflict)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING created_at`,
		sv.ID, sv.DisplayName, sv.LastIP, sv.LastSeenAt, sv.AgentStatus,
		sv.UsesCustomConfig, sv.ConfigVersion,
		nullableJSON(sv.AgentLocalConfig), sv.AgentLocalConfigHash, sv.AgentLocalConfigUpdatedAt,
		nullableJSON(sv.PendingLocalConfig), sv.PendingLocalConfigBaseHash, sv.PendingLocalConfigRevision,
		sv.LocalConfigConflict,
	).Scan(&sv.CreatedAt)
	return mapErr("create server", err)
}

func (s *Store) GetServer(ctx context.Context, id uuid.UUID) (*domain.Server, error) {
	return queryOne(ctx, s.q, "get server", scanServer,
		`SELECT `+serverCols+` FROM servers WHERE id = $1`, id)
}

func (s *Store) ListServers(ctx context.Context) ([]domain.Server, error) {
	return queryAll(ctx, s.q, "list servers", scanServer,
		`SELECT `+serverCols+` FROM servers ORDER BY created_at`)
}

func (s *Store) UpdateServer(ctx context.Context, sv *domain.Server) error {
	return execOne(ctx, s.q, "update server", `
		UPDATE servers
		SET display_name = $2, last_ip = $3, last_seen_at = $4, agent_status = $5,
		    uses_custom_config = $6, config_version = $7,
		    agent_local_config = $8, agent_local_config_hash = $9, agent_local_config_updated_at = $10,
		    pending_local_config = $11, pending_local_config_base_hash = $12,
		    pending_local_config_revision = $13, local_config_conflict = $14
		WHERE id = $1`,
		sv.ID, sv.DisplayName, sv.LastIP, sv.LastSeenAt, sv.AgentStatus,
		sv.UsesCustomConfig, sv.ConfigVersion,
		nullableJSON(sv.AgentLocalConfig), sv.AgentLocalConfigHash, sv.AgentLocalConfigUpdatedAt,
		nullableJSON(sv.PendingLocalConfig), sv.PendingLocalConfigBaseHash, sv.PendingLocalConfigRevision,
		sv.LocalConfigConflict)
}

func (s *Store) DeleteServer(ctx context.Context, id uuid.UUID) error {
	return execOne(ctx, s.q, "delete server", `DELETE FROM servers WHERE id = $1`, id)
}

// GetServerByIP returns the most recently seen non-deleted server with the given last IP.
func (s *Store) GetServerByIP(ctx context.Context, ip netip.Addr) (*domain.Server, error) {
	return queryOne(ctx, s.q, "get server by ip", scanServer, `
		SELECT `+serverCols+` FROM servers
		WHERE last_ip = $1 AND agent_status <> $2
		ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
		LIMIT 1`, ip, domain.ServerDeleted)
}

// Enrollments

const enrollCols = `id, remote_ip, client_name, status, reason, previous_server_id,
	previous_key_prefix, presented_key_prefix, last_seen_at, created_at, decided_at,
	decided_by, server_id`

func scanEnrollment(r rowScanner) (domain.AgentEnrollment, error) {
	var e domain.AgentEnrollment
	err := r.Scan(&e.ID, &e.RemoteIP, &e.ClientName, &e.Status, &e.Reason, &e.PreviousServerID,
		&e.PreviousKeyPrefix, &e.PresentedKeyPrefix, &e.LastSeenAt, &e.CreatedAt, &e.DecidedAt,
		&e.DecidedBy, &e.ServerID)
	return e, err
}

// CreateEnrollment inserts e. Only one pending enrollment per IP may exist;
// a second one yields domain.ErrConflict.
func (s *Store) CreateEnrollment(ctx context.Context, e *domain.AgentEnrollment) error {
	e.ID = newID(e.ID)
	if e.Status == "" {
		e.Status = domain.EnrollPending
	}
	if e.Reason == "" {
		e.Reason = domain.ReasonFirstSeen
	}
	err := s.q.QueryRow(ctx, `
		INSERT INTO agent_enrollments (id, remote_ip, client_name, status, reason,
			previous_server_id, previous_key_prefix, presented_key_prefix, last_seen_at,
			decided_at, decided_by, server_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()), $10, $11, $12)
		RETURNING last_seen_at, created_at`,
		e.ID, e.RemoteIP, e.ClientName, e.Status, e.Reason,
		e.PreviousServerID, e.PreviousKeyPrefix, e.PresentedKeyPrefix, timeOrNil(e.LastSeenAt),
		e.DecidedAt, e.DecidedBy, e.ServerID,
	).Scan(&e.LastSeenAt, &e.CreatedAt)
	return mapErr("create enrollment", err)
}

func (s *Store) GetPendingEnrollmentByIP(ctx context.Context, ip netip.Addr) (*domain.AgentEnrollment, error) {
	return queryOne(ctx, s.q, "get pending enrollment", scanEnrollment,
		`SELECT `+enrollCols+` FROM agent_enrollments WHERE remote_ip = $1 AND status = $2`,
		ip, domain.EnrollPending)
}

func (s *Store) GetLatestEnrollmentByIP(ctx context.Context, ip netip.Addr) (*domain.AgentEnrollment, error) {
	return queryOne(ctx, s.q, "get latest enrollment", scanEnrollment,
		`SELECT `+enrollCols+` FROM agent_enrollments WHERE remote_ip = $1
		 ORDER BY created_at DESC, id LIMIT 1`, ip)
}

// ListEnrollments lists enrollments, newest first; an empty status returns all.
func (s *Store) ListEnrollments(ctx context.Context, status string) ([]domain.AgentEnrollment, error) {
	return queryAll(ctx, s.q, "list enrollments", scanEnrollment, `
		SELECT `+enrollCols+` FROM agent_enrollments
		WHERE ($1::text = '' OR status = $1::text)
		ORDER BY created_at DESC`, status)
}

func (s *Store) UpdateEnrollment(ctx context.Context, e *domain.AgentEnrollment) error {
	return execOne(ctx, s.q, "update enrollment", `
		UPDATE agent_enrollments
		SET remote_ip = $2, client_name = $3, status = $4, reason = $5,
		    previous_server_id = $6, previous_key_prefix = $7, presented_key_prefix = $8,
		    last_seen_at = COALESCE($9, last_seen_at), decided_at = $10, decided_by = $11, server_id = $12
		WHERE id = $1`,
		e.ID, e.RemoteIP, e.ClientName, e.Status, e.Reason,
		e.PreviousServerID, e.PreviousKeyPrefix, e.PresentedKeyPrefix, timeOrNil(e.LastSeenAt),
		e.DecidedAt, e.DecidedBy, e.ServerID)
}

func (s *Store) GetEnrollment(ctx context.Context, id uuid.UUID) (*domain.AgentEnrollment, error) {
	return queryOne(ctx, s.q, "get enrollment", scanEnrollment,
		`SELECT `+enrollCols+` FROM agent_enrollments WHERE id = $1`, id)
}

// Agent keys

const agentKeyCols = `id, server_id, key_prefix, key_hash, created_at, expires_at, revoked_at,
	last_used_at, label`

func scanAgentKey(r rowScanner) (domain.AgentKey, error) {
	var k domain.AgentKey
	err := r.Scan(&k.ID, &k.ServerID, &k.KeyPrefix, &k.KeyHash, &k.CreatedAt, &k.ExpiresAt,
		&k.RevokedAt, &k.LastUsedAt, &k.Label)
	return k, err
}

func (s *Store) CreateAgentKey(ctx context.Context, k *domain.AgentKey) error {
	k.ID = newID(k.ID)
	err := s.q.QueryRow(ctx, `
		INSERT INTO agent_keys (id, server_id, key_prefix, key_hash, created_at, expires_at, label)
		VALUES ($1, $2, $3, $4, COALESCE($5, now()), $6, $7)
		RETURNING created_at`,
		k.ID, k.ServerID, k.KeyPrefix, k.KeyHash, timeOrNil(k.CreatedAt), k.ExpiresAt, k.Label,
	).Scan(&k.CreatedAt)
	return mapErr("create agent key", err)
}

// GetAgentKeyByHash returns the key only if it is not revoked and not expired.
func (s *Store) GetAgentKeyByHash(ctx context.Context, hash []byte) (*domain.AgentKey, error) {
	return queryOne(ctx, s.q, "get agent key", scanAgentKey, `
		SELECT `+agentKeyCols+` FROM agent_keys
		WHERE key_hash = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY created_at DESC
		LIMIT 1`, hash)
}

func (s *Store) ListAgentKeys(ctx context.Context, serverID uuid.UUID) ([]domain.AgentKey, error) {
	return queryAll(ctx, s.q, "list agent keys", scanAgentKey,
		`SELECT `+agentKeyCols+` FROM agent_keys WHERE server_id = $1 ORDER BY created_at DESC`,
		serverID)
}

// RevokeAgentKey marks the key revoked at the given time; an already revoked key keeps its original time.
func (s *Store) RevokeAgentKey(ctx context.Context, id uuid.UUID, at time.Time) error {
	return execOne(ctx, s.q, "revoke agent key",
		`UPDATE agent_keys SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`, id, at)
}

func (s *Store) TouchAgentKey(ctx context.Context, id uuid.UUID, at time.Time) error {
	return execOne(ctx, s.q, "touch agent key",
		`UPDATE agent_keys SET last_used_at = $2 WHERE id = $1`, id, at)
}

func (s *Store) SetAgentKeyExpiry(ctx context.Context, id uuid.UUID, expiresAt time.Time) error {
	return execOne(ctx, s.q, "set agent key expiry",
		`UPDATE agent_keys SET expires_at = $2 WHERE id = $1`, id, expiresAt)
}

// ActiveKeyPrefix returns the prefix of the most recently created key of the
// server that is not revoked and not expired, or domain.ErrNotFound.
func (s *Store) ActiveKeyPrefix(ctx context.Context, serverID uuid.UUID) (string, error) {
	var prefix string
	err := s.q.QueryRow(ctx, `
		SELECT key_prefix FROM agent_keys
		WHERE server_id = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY created_at DESC
		LIMIT 1`, serverID).Scan(&prefix)
	if err != nil {
		return "", mapErr("active key prefix", err)
	}
	return prefix, nil
}

// Agent configuration

func (s *Store) GetAgentDefaults(ctx context.Context) (*domain.AgentDefaults, error) {
	return queryOne(ctx, s.q, "get agent defaults", func(r rowScanner) (domain.AgentDefaults, error) {
		var d domain.AgentDefaults
		err := r.Scan(&d.Config, &d.ConfigVersion, &d.UpdatedAt)
		return d, err
	}, `SELECT config, config_version, updated_at FROM agent_defaults WHERE id = 1`)
}

// UpdateAgentDefaults replaces the single agent_defaults row (id=1) with cfg
// and sets config_version to version.
func (s *Store) UpdateAgentDefaults(ctx context.Context, cfg []byte, version int64) error {
	return execOne(ctx, s.q, "update agent defaults", `
		UPDATE agent_defaults SET config = $1, config_version = $2, updated_at = now()
		WHERE id = 1`, jsonOrDefault(cfg, "{}"), version)
}

func (s *Store) GetServerConfig(ctx context.Context, serverID uuid.UUID) (*domain.ServerConfig, error) {
	return queryOne(ctx, s.q, "get server config", func(r rowScanner) (domain.ServerConfig, error) {
		var c domain.ServerConfig
		err := r.Scan(&c.ServerID, &c.Config, &c.ConfigVersion, &c.UpdatedAt)
		return c, err
	}, `SELECT server_id, config, config_version, updated_at FROM server_configs WHERE server_id = $1`,
		serverID)
}

// UpsertServerConfig stores the per-server config. A positive ConfigVersion is
// stored as-is; otherwise it starts at 1 or is incremented. On return sc carries
// the stored version and timestamp.
func (s *Store) UpsertServerConfig(ctx context.Context, sc *domain.ServerConfig) error {
	err := s.q.QueryRow(ctx, `
		INSERT INTO server_configs (server_id, config, config_version)
		VALUES ($1, $2, GREATEST($3::bigint, 1))
		ON CONFLICT (server_id) DO UPDATE
		SET config = EXCLUDED.config,
		    config_version = CASE WHEN $3::bigint > 0 THEN $3::bigint
		                          ELSE server_configs.config_version + 1 END,
		    updated_at = now()
		RETURNING config_version, updated_at`,
		sc.ServerID, jsonOrDefault(sc.Config, "{}"), sc.ConfigVersion,
	).Scan(&sc.ConfigVersion, &sc.UpdatedAt)
	return mapErr("upsert server config", err)
}

func (s *Store) DeleteServerConfig(ctx context.Context, serverID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM server_configs WHERE server_id = $1`, serverID)
	return mapErr("delete server config", err)
}

// Domain <-> server assignment

const domainServerCols = `domain_id, server_id, install_mode, cert_path, key_path, chain_path,
	fullchain_path, restart_override, created_at, updated_at`

func scanDomainServer(r rowScanner) (domain.DomainServer, error) {
	var ds domain.DomainServer
	err := r.Scan(&ds.DomainID, &ds.ServerID, &ds.InstallMode, &ds.CertPath, &ds.KeyPath,
		&ds.ChainPath, &ds.FullchainPath, &ds.RestartOverride, &ds.CreatedAt, &ds.UpdatedAt)
	return ds, err
}

// UpsertDomainServer inserts or updates the (domain, server) assignment.
// An empty InstallMode defaults to "symlink"; an empty RestartOverride is stored as NULL.
func (s *Store) UpsertDomainServer(ctx context.Context, ds *domain.DomainServer) error {
	if ds.InstallMode == "" {
		ds.InstallMode = "symlink"
	}
	err := s.q.QueryRow(ctx, `
		INSERT INTO domain_servers (domain_id, server_id, install_mode, cert_path, key_path,
			chain_path, fullchain_path, restart_override)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (domain_id, server_id) DO UPDATE
		SET install_mode = EXCLUDED.install_mode,
		    cert_path = EXCLUDED.cert_path,
		    key_path = EXCLUDED.key_path,
		    chain_path = EXCLUDED.chain_path,
		    fullchain_path = EXCLUDED.fullchain_path,
		    restart_override = EXCLUDED.restart_override,
		    updated_at = now()
		RETURNING created_at, updated_at`,
		ds.DomainID, ds.ServerID, ds.InstallMode, ds.CertPath, ds.KeyPath, ds.ChainPath,
		ds.FullchainPath, nullableJSON(ds.RestartOverride),
	).Scan(&ds.CreatedAt, &ds.UpdatedAt)
	return mapErr("upsert domain server", err)
}

func (s *Store) DeleteDomainServer(ctx context.Context, domainID, serverID uuid.UUID) error {
	return execOne(ctx, s.q, "delete domain server",
		`DELETE FROM domain_servers WHERE domain_id = $1 AND server_id = $2`, domainID, serverID)
}

func (s *Store) ListDomainServersByServer(ctx context.Context, serverID uuid.UUID) ([]domain.DomainServer, error) {
	return queryAll(ctx, s.q, "list domain servers by server", scanDomainServer,
		`SELECT `+domainServerCols+` FROM domain_servers WHERE server_id = $1 ORDER BY domain_id`,
		serverID)
}

func (s *Store) ListDomainServersByDomain(ctx context.Context, domainID uuid.UUID) ([]domain.DomainServer, error) {
	return queryAll(ctx, s.q, "list domain servers by domain", scanDomainServer,
		`SELECT `+domainServerCols+` FROM domain_servers WHERE domain_id = $1 ORDER BY server_id`,
		domainID)
}
