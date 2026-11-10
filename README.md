# TLS herd

TLS herd keeps TLS certificates for many hosts in one place and rolls them out
safely. A central **server** stores certificates per domain (with versions and
rollback); a small **agent** on every host polls the server, installs assigned
certificates, runs **pre-start validation**, **restarts/reloads** the local
service, and reports the result. Operators work in an embedded web UI or the JSON API.

| Path | Role |
| --- | --- |
| `cmd/tlsherd-server` | Control plane: JSON API, agent API, web UI, monitor + notification workers |
| `cmd/tlsherd-agent` | Per-host agent |
| `migrations/schema.sql` | Canonical PostgreSQL schema (from scratch) |
| `deploy/` | docker-compose, systemd units, sample env / `agent.local.cfg` |
| `Dockerfile` | Multi-stage image for `tlsherd-server` |

## Documentation

| Doc | Contents |
| --- | --- |
| **[Agent guide](docs/agent.md)** | Host install, `agent.local.cfg` / schedule config, **web service × start method**, full JSON examples (nginx+systemd, nginx+docker, custom command) |
| **[Server configuration](docs/configuration.md)** | `TLSHERD_*` env, listeners, notifications |
| **[Operations](docs/operations.md)** | Backup, restore, rollback, operator cheat sheet |
| **[Deploy samples](deploy/README.md)** | Compose, unit files, sample configs |

## Architecture

```
browser ──HTTPS──► :8443 admin  ──┐
  (web UI, API)                   |
                                  ├─► tlsherd-server ──► PostgreSQL
                                  |   handler ─► service ─► store
agents  ──HTTPS──► :8444 agent  ──┘              └── data dir (PEM files, 0600)
  (poll, Bearer key + source IP)
```

Admin and agent APIs use **separate TCP listeners** so firewalls can expose only the
agent port to managed hosts while keeping the UI/API on a private network.

Layers (`handler → service → store`, no reverse dependencies):

| Package | Role |
| --- | --- |
| `internal/handler` | HTTP transport: `/api/v1`, sessions, CSRF, rate limits, panic recovery |
| `internal/ui` | Embedded web UI (templates + static assets) |
| `internal/service` | Business logic, authz, audit/events, certificate storage |
| `internal/store/postgres` | Persistence (pgx); transactions driven by the service layer |
| `internal/agent`, `internal/agentcfg` | Agent engine and config documents |

### Key behaviors

- **Authentication.** Opaque session cookie (`tlsherd_session`, idle 12 h / max 24 h).
  Cookie mutations need `X-CSRF-Token` = `tlsherd_csrf`. Bearer tokens skip CSRF.
  Minimum password length is 8.
- **Roles.** `admin` can do everything. `operator` access is per group
  (`can_read`, `can_write_config`, `can_write_certs`). Domains may have zero or more groups.
- **Agent identity.** Source IP + API key. First contact → enrollment queue; admin
  accepts (optional name / link existing server). Keys hashed at rest; rotate (24 h
  overlap) or revoke. IP/key mismatch is blocked and queued for review.
- **Two agent config layers.** (1) **Local** `agent.local.cfg` — web service, pre-start
  validation, start method (`systemd` / `docker` / `exec`), install paths (agent
  priority; server UI can queue an update that the agent pulls). (2) **Schedule**
  `config.cfg` — poll/window/backups/post-check (server-authoritative). Details:
  [Agent guide](docs/agent.md).
- **Certificates.** Leaf or fullchain PEM; key must match for domain server certs. Immutable
  versions + rollback. Files under `<data_dir>/certs/<sha256>/` and
  `<data_dir>/domains/<fqdn>/current`.
- **Managed certificates.** Inventory outside domain deploy: `ca` / `allowed_client`
  (cert-only) and `mtls_client` (cert+key, agent-deployable). Optional domain link; linked
  CAs are checked against the domain leaf. Expiry scanning and confirm-on-identity-change
  apply. See [Operations](docs/operations.md).
- **Monitor.** Probes endpoints (agent last IP or custom dial address; optional mTLS client
  cert); global settings + per-endpoint interval; events for down / expiry / mismatch.
- **Events.** Open alarms close on success or **Dismiss**. Instant types are stored resolved.
- **Notifications.** Non-login accounts (email / Telegram / webhook), scopes, working hours.
  Open + resolve delivery with duration. See [Server configuration](docs/configuration.md).

### Web UI

Served at `/` by the same binary; no frontend build step. Pages include Dashboard,
Enrollments, Domains, Managed certs, Servers (tabbed: Server / Domains / Endpoints /
**Agent local config** / Schedule), Agent defaults, Monitor settings, Notifications,
Events, Groups, Users, Monitor, Account.

## Threat model

**Assets:** private keys of managed domains, ability to run commands on agent hosts,
and the PostgreSQL database.

**The agent runs commands as root** (unit user). Host-local `agent.local.cfg` owns
web service, pre-start validation, start method, and paths. Anyone who can edit that
file (on the host or via a queued server-side update the agent pulls) has **root on that host**. Schedule
settings remain server-authoritative in `config.cfg`. Domain `restart_override` is a
last-resort per-domain overlay.

- Keep the admin group small; protect the server like a jump host.
- Local-config and schedule edits require confirmation; review audit / `agent_config_updated`.
- Commands are argv lists, never a shell. Paths stay under the cert root.
- Agents must use HTTPS and verify the server cert (`TLSHERD_CA_FILE`). Never use
  `--insecure-http` / `--insecure-skip-verify` across untrusted networks.
- Private keys at rest are PEM files (0600), not app-encrypted — use disk encryption.

**Out of scope for the MVP:** HSM/KMS, per-domain restart authorization, multi-person
approval, SSO/MFA.

## Deploy (quick start)

### Requirements

Go 1.27, PostgreSQL 14+ (`citext`, `pgcrypto`), systemd on agent hosts.

```sh
make build            # bin/tlsherd-server, bin/tlsherd-agent
sudo install -m 0755 bin/tlsherd-server /usr/local/bin/
sudo install -m 0755 bin/tlsherd-agent /usr/local/bin/        # on every managed host
```

### Server + PostgreSQL (Compose)

```sh
export TLSHERD_DB_PASSWORD='long-random-password'
# Lab default: plain HTTP. For HTTPS see comments in deploy/docker-compose.yml.
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs server | grep -i bootstrap
```

| Port | Purpose |
| --- | --- |
| `8443` | Admin UI + JSON API |
| `8444` | Agent API only |

On first start the server creates the bootstrap admin and logs a temporary password
at WARN. Sign in, change the password on **Account**, then create users/groups.

Existing Postgres:

```sh
createdb tlsherd
export TLSHERD_DATABASE_URL='postgres://tlsherd:PASSWORD@127.0.0.1:5432/tlsherd?sslmode=disable'
make schema
```

`migrations/schema.sql` is the complete from-scratch schema. For upgrades, apply ordered
`ALTER`/`UPDATE` statements from release notes — do not re-run the schema file on a
populated database.

Full env reference: [Server configuration](docs/configuration.md).

### Systemd server (sketch)

```sh
sudo useradd --system --home /var/lib/tlsherd --shell /usr/sbin/nologin tlsherd
sudo install -d -m 0750 -o root -g tlsherd /etc/tlsherd
sudo install -m 0640 -o root -g tlsherd deploy/server.env /etc/tlsherd/server.env   # edit first
sudo install -m 0644 deploy/tlsherd-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tlsherd-server
```

### Agents

See **[Agent guide](docs/agent.md)** for install, `agent.local.cfg` examples
(nginx+systemd, nginx+docker, custom command), and schedule config.

Point agents at the **agent** listener: `TLSHERD_SERVER_URL=https://…:8444`.

## Development

```sh
make check                      # go vet + go test ./...
go build ./cmd/... ./internal/...
make run-server                 # needs TLSHERD_*; use --insecure-http locally
```
