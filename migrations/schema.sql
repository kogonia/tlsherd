-- TLS herd canonical schema (from scratch).
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    login                   citext NOT NULL UNIQUE,
    display_name            text NOT NULL DEFAULT '',
    password_hash           text NOT NULL,
    role                    text NOT NULL CHECK (role IN ('admin', 'operator')),
    is_active               boolean NOT NULL DEFAULT true,
    must_change_password    boolean NOT NULL DEFAULT false,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    last_login_at           timestamptz
);

CREATE TABLE sessions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    ip              inet,
    user_agent      text
);

CREATE TABLE groups (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            citext NOT NULL UNIQUE,
    description     text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE domains (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fqdn            citext NOT NULL UNIQUE,
    notes           text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE domain_groups (
    domain_id       uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    group_id        uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (domain_id, group_id)
);

CREATE TABLE group_permissions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id            uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    can_read            boolean NOT NULL DEFAULT false,
    can_write_config    boolean NOT NULL DEFAULT false,
    can_write_certs     boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, group_id)
);

CREATE TABLE certificates (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_sha256  text NOT NULL UNIQUE,
    subject_cn          text NOT NULL DEFAULT '',
    sans                jsonb NOT NULL DEFAULT '[]',
    issuer_cn           text NOT NULL DEFAULT '',
    serial              text NOT NULL DEFAULT '',
    not_before          timestamptz NOT NULL,
    not_after           timestamptz NOT NULL,
    key_algo            text NOT NULL DEFAULT '',
    key_bits            int NOT NULL DEFAULT 0,
    cert_path           text NOT NULL,
    key_path            text NOT NULL,
    chain_path          text NOT NULL DEFAULT '',
    uploaded_at         timestamptz NOT NULL DEFAULT now(),
    uploaded_by         uuid REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX certificates_not_after_idx ON certificates(not_after);

CREATE TABLE domain_certificates (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    certificate_id      uuid NOT NULL REFERENCES certificates(id) ON DELETE RESTRICT,
    version             int NOT NULL,
    is_current          boolean NOT NULL DEFAULT false,
    activated_at        timestamptz NOT NULL DEFAULT now(),
    deactivated_at      timestamptz,
    activated_by        uuid REFERENCES users(id) ON DELETE SET NULL,
    reason              text NOT NULL DEFAULT '',
    UNIQUE (domain_id, version)
);

CREATE UNIQUE INDEX domain_certificates_current_idx
    ON domain_certificates(domain_id) WHERE is_current;

CREATE TABLE servers (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name        text,
    last_ip             inet,
    last_seen_at        timestamptz,
    agent_status        text NOT NULL DEFAULT 'active'
                        CHECK (agent_status IN ('active', 'blocked_identity', 'offline', 'deleted')),
    uses_custom_config  boolean NOT NULL DEFAULT false,
    config_version      bigint NOT NULL DEFAULT 0,
    agent_local_config              jsonb,
    agent_local_config_hash         text NOT NULL DEFAULT '',
    agent_local_config_updated_at   timestamptz,
    pending_local_config            jsonb,
    pending_local_config_base_hash  text NOT NULL DEFAULT '',
    pending_local_config_revision   bigint NOT NULL DEFAULT 0,
    local_config_conflict           boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_enrollments (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    remote_ip               inet NOT NULL,
    client_name             text,
    status                  text NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'accepted', 'rejected')),
    reason                  text NOT NULL DEFAULT 'first_seen',
    previous_server_id      uuid REFERENCES servers(id) ON DELETE SET NULL,
    previous_key_prefix     text,
    presented_key_prefix    text,
    last_seen_at            timestamptz NOT NULL DEFAULT now(),
    created_at              timestamptz NOT NULL DEFAULT now(),
    decided_at              timestamptz,
    decided_by              uuid REFERENCES users(id) ON DELETE SET NULL,
    server_id               uuid REFERENCES servers(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX agent_enrollments_pending_ip_idx
    ON agent_enrollments(remote_ip) WHERE status = 'pending';

CREATE TABLE agent_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    key_prefix      text NOT NULL,
    key_hash        bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    revoked_at      timestamptz,
    last_used_at    timestamptz,
    label           text NOT NULL DEFAULT ''
);

CREATE INDEX agent_keys_hash_idx ON agent_keys(key_hash);

CREATE TABLE agent_defaults (
    id              int PRIMARY KEY CHECK (id = 1),
    config          jsonb NOT NULL DEFAULT '{}',
    config_version  bigint NOT NULL DEFAULT 1,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

INSERT INTO agent_defaults (id, config, config_version) VALUES (1, '{}', 1);

CREATE TABLE server_configs (
    server_id       uuid PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    config          jsonb NOT NULL DEFAULT '{}',
    config_version  bigint NOT NULL DEFAULT 1,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE domain_servers (
    domain_id           uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    server_id           uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    install_mode        text NOT NULL DEFAULT 'symlink'
                        CHECK (install_mode IN ('symlink', 'copy')),
    cert_path           text NOT NULL DEFAULT '',
    key_path            text NOT NULL DEFAULT '',
    chain_path          text NOT NULL DEFAULT '',
    fullchain_path      text NOT NULL DEFAULT '',
    restart_override    jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id, server_id)
);

CREATE TABLE server_endpoints (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    host            text NOT NULL,
    port            int NOT NULL DEFAULT 443,
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (server_id, domain_id, host, port)
);

CREATE TABLE monitor_results (
    id                  bigserial PRIMARY KEY,
    endpoint_id         uuid NOT NULL REFERENCES server_endpoints(id) ON DELETE CASCADE,
    checked_at          timestamptz NOT NULL DEFAULT now(),
    reachable           boolean NOT NULL DEFAULT false,
    tls_ok              boolean NOT NULL DEFAULT false,
    peer_fingerprint    text,
    peer_not_after      timestamptz,
    issuer              text,
    error               text,
    latency_ms          int,
    connected_ip        inet
);

CREATE INDEX monitor_results_endpoint_checked_idx
    ON monitor_results(endpoint_id, checked_at DESC);

CREATE TABLE events (
    id                  bigserial PRIMARY KEY,
    at                  timestamptz NOT NULL DEFAULT now(),
    type                text NOT NULL,
    severity            text NOT NULL DEFAULT 'info',
    domain_id           uuid REFERENCES domains(id) ON DELETE SET NULL,
    server_id           uuid REFERENCES servers(id) ON DELETE SET NULL,
    certificate_id      uuid REFERENCES certificates(id) ON DELETE SET NULL,
    group_id            uuid REFERENCES groups(id) ON DELETE SET NULL,
    message             text NOT NULL DEFAULT '',
    details             jsonb NOT NULL DEFAULT '{}',
    dedup_key           text,
    resolved_at         timestamptz,
    actor_user_id       uuid REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX events_resolved_at_idx ON events(resolved_at, at DESC);
CREATE UNIQUE INDEX events_open_dedup_idx ON events(dedup_key) WHERE resolved_at IS NULL AND dedup_key IS NOT NULL;

CREATE TABLE audit_log (
    id                  bigserial PRIMARY KEY,
    at                  timestamptz NOT NULL DEFAULT now(),
    actor_user_id       uuid REFERENCES users(id) ON DELETE SET NULL,
    action              text NOT NULL,
    entity_type         text NOT NULL,
    entity_id           text NOT NULL DEFAULT '',
    details             jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_log_at_idx ON audit_log(at DESC);

CREATE TABLE system_settings (
    key         text PRIMARY KEY,
    value       jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value) VALUES
    ('monitor', '{"interval":"5m","timeout":"10s","expiring_soon":"720h"}'),
    ('notifications', '{"smtp":{"host":"","port":587,"username":"","password":"","from":"","tls":"starttls"},"telegram":{"bot_token":""},"worker":{"interval":"15s","batch":50,"max_attempts":8}}');

CREATE TABLE notification_accounts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    allow_all       boolean NOT NULL DEFAULT false,
    event_types     text[] NOT NULL DEFAULT '{}',
    timezone        text NOT NULL DEFAULT 'UTC',
    window_days     int[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
    window_from     text NOT NULL DEFAULT '00:00',
    window_to       text NOT NULL DEFAULT '24:00',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_scopes (
    account_id      uuid NOT NULL REFERENCES notification_accounts(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('domain', 'group', 'server')),
    target_id       uuid NOT NULL,
    PRIMARY KEY (account_id, kind, target_id)
);

CREATE INDEX notification_scopes_target_idx ON notification_scopes(kind, target_id);

CREATE TABLE notification_destinations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES notification_accounts(id) ON DELETE CASCADE,
    channel         text NOT NULL CHECK (channel IN ('email', 'telegram', 'webhook')),
    config          jsonb NOT NULL DEFAULT '{}',
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX notification_destinations_account_idx ON notification_destinations(account_id);

CREATE TABLE notification_outbox (
    id                  bigserial PRIMARY KEY,
    event_id            bigint NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    destination_id      uuid NOT NULL REFERENCES notification_destinations(id) ON DELETE CASCADE,
    kind                text NOT NULL CHECK (kind IN ('opened', 'resolved')),
    payload             jsonb NOT NULL DEFAULT '{}',
    status              text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
    attempts            int NOT NULL DEFAULT 0,
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    last_error          text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    sent_at             timestamptz,
    UNIQUE (event_id, destination_id, kind)
);

CREATE INDEX notification_outbox_pending_idx
    ON notification_outbox(next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX notification_outbox_event_idx ON notification_outbox(event_id);

CREATE TABLE apply_results (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    apply_id        text NOT NULL UNIQUE,
    server_id       uuid NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    domain_id       uuid REFERENCES domains(id) ON DELETE SET NULL,
    status          text NOT NULL,
    message         text NOT NULL DEFAULT '',
    details         jsonb NOT NULL DEFAULT '{}',
    reported_at     timestamptz NOT NULL DEFAULT now()
);
