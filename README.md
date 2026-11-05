# TLS herd

TLS herd keeps TLS certificates for many hosts in one place and rolls them out
safely. A central **server** stores certificates per domain (with versions and
rollback); a small **agent** on every host polls the server, installs assigned
certificates, verifies and restarts the local service, and reports the result.
Operators work in an embedded web UI or the JSON API.

- `cmd/tlsherd-server` – control plane: JSON API, agent API, web UI, monitor + notification workers
- `cmd/tlsherd-agent` – per-host agent
- `migrations/schema.sql` – canonical PostgreSQL schema (from scratch)
- `deploy/` – docker-compose (server + PostgreSQL), systemd units, sample env files
- `Dockerfile` – multi-stage image for `tlsherd-server`

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
| `internal/handler` | HTTP transport: `/api/v1` routes, sessions, CSRF, rate limits, panic recovery |
| `internal/ui` | Embedded web UI (templates + static assets, see below) |
| `internal/service` | Business logic, authorization checks, audit and events, certificate storage |
| `internal/store/postgres` | Persistence (pgx); transactions are driven by the service layer |
| `internal/agent`, `internal/agentcfg` | Agent engine and the server-authoritative agent config document |

Key behaviors:

- **Authentication.** Users log in with login/password and get an opaque session
  token (cookie `tlsherd_session`, HttpOnly, idle timeout 12 h, max 24 h).
  Cookie-authenticated mutations must send `X-CSRF-Token` equal to the
  `tlsherd_csrf` cookie. Bearer tokens (scripts) are exempt from CSRF.
  Minimum password length is 8 characters.
- **Roles.** `admin` can do everything. `operator` access is granted per group
  (`can_read`, `can_write_config`, `can_write_certs`). Domains may have **zero or
  more** groups (groups are for access control only; ungrouped domains are
  visible to admins and still accept certificates and monitoring).
- **Agent identity.** An agent is identified by its source IP plus its API key.
  First contact lands in an enrollment queue; an admin accepts it (optionally
  naming it, or linking it to an existing server after an IP/key change). The key
  is delivered to the agent once; only a hash is stored. Keys can be rotated
  (old keys work for 24 h) or revoked. A known key from a new IP, or a known IP
  with the wrong key, is **blocked and queued for review** instead of served.
- **Two config layers on the agent.** (1) **Local** `agent.local.cfg` — service
  type, pre-start verify, restart, install layout (agent priority; server UI can
  push edits). (2) **Schedule** `config.cfg` — poll/enroll intervals, maintenance
  window, backups, post-check (server-authoritative defaults or per-server doc).
- **Certificates.** Uploads accept a single leaf or a fullchain PEM (leaf first,
  intermediates follow). Key must match; domain coverage mismatch needs explicit
  confirmation. Each upload is an immutable version; rollback selects any older
  version. Server files live under `<data_dir>/certs/<sha256>/` and
  `<data_dir>/domains/<fqdn>/current`.
- **Monitor.** A background worker probes configured endpoints (host:port) and raises
  events for unreachable endpoints, expired/expiring certificates and endpoints that
  serve a different certificate than the current one.
- **Events.** Open (alarm) events do not expire; they close when a later success
  resolves their dedup key, or when an operator uses **Dismiss**. Point-in-time
  events (`agent_accepted`, `agent_rejected`, `agent_config_updated`, cert upload
  confirmations/rejections, rollbacks) are stored already resolved and never sit
  in the open queue.
- **Notifications.** Separate non-login *notification accounts* (not UI users)
  receive alerts over email (SMTP), Telegram, or webhooks. Each account has an
  event-type allowlist (new accounts default to certificate expiration/validation
  types), optional Allow-all or domain/group/server scopes, enable flag, timezone,
  and working days/hours. Delivery is queued: **opened** when a new open event is
  inserted, and **resolved** when it closes (payload includes start, end, duration).
  Outside the working window, sends are deferred. The Events table shows a notify
  rollup (`—` / pending / sent / partial / failed / skipped) expandable to
  account, channel, and status.

### Web UI

Served at `/` by the same binary; no frontend build step and no CDN: templates,
CSS, JavaScript and a vendored HTMX are embedded with `embed.FS`.

- Pages: Login, Dashboard, Enrollments, Domains (upload PEM / fullchain, versions,
  rollback, assign servers/paths), Servers (rename, rotate/revoke key, **Agent local
  config**, schedule config + force from defaults), Agent defaults, **Notifications**
  (SMTP/Telegram/worker) and **Notification accounts**, Events (dismiss, notify
  status, audit for admins), Groups, Users, Monitor, Account (forced password
  change after bootstrap). Time zone fields use a searchable IANA picker
  (name + offset).
- The HTML pages are shells; `static/app.js` calls the JSON API with the session
  cookie. Authorization is enforced in the service layer.
- Responses carry a strict Content-Security-Policy (same-origin scripts and styles
  only, no inline script, no framing).

## Threat model

**Assets:** private keys of all managed domains, the ability to run commands on
every agent host, and the PostgreSQL database.

**The agent runs commands as root.** Host-local `agent.local.cfg` (default
`/var/lib/tlsherd-agent/agent.local.cfg`) owns service type, pre-start verify, restart
(`systemd`/`docker`/`exec`), and cert/install paths. The agent reports that file to
the server on enroll/poll; an admin **Edit** on the server page queues a push that
the agent writes back into the same file (keeping one `agent.local.cfg.prev`). Anyone
who can edit that local config (on the host or via the server UI) therefore has
**root on that host**. Schedule settings (poll/window/backups) remain server-authoritative
in `config.cfg` in the same agent directory. Domain `restart_override` is a last-resort
per-domain overlay.

- Treat server admins as root on agent hosts. Keep the admin group small, use strong
  unique passwords, and protect the server host like a jump host.
- Local-config pushes and schedule edits require confirmation; schedule changes emit
  `agent_config_updated` / audit entries. Review them.
- Commands are argv lists, never a shell. Certificate paths stay under the cert root.
  Adjust `User=`, `ReadWritePaths=` (include `TLSHERD_AGENT_DIR`) together with the unit.
- Operators with `can_write_config` can push local config to servers in their groups.

**Agent ↔ server channel.** Agents must use HTTPS and verify the server certificate
(`TLSHERD_CA_FILE` for a private CA). A man in the middle could feed agents arbitrary
config and certificates, so never use `--insecure-http` or the agent's
`--insecure-skip-verify` across untrusted networks. The agent API key is bound to
the source IP and is useless from other addresses; behind a proxy, `TLSHERD_TRUST_PROXY=1`
is only safe if the proxy overwrites `X-Forwarded-For`.

**At rest.** Private keys are stored as PEM files (mode 0600, directory 0750) under the
data dir, not encrypted by the application. Use disk encryption and restrict access to the
data dir and database backups. Passwords are stored as hashes; agent keys as SHA-256 hashes.

**Out of scope for the MVP:** HSM/KMS key storage, per-domain restart authorization,
multi-person approval of config changes, SSO/MFA.

## Deploy

### Requirements

Go 1.27, PostgreSQL 14+ (extensions `citext`, `pgcrypto`), systemd on the hosts.

```sh
make build            # bin/tlsherd-server, bin/tlsherd-agent
sudo install -m 0755 bin/tlsherd-server /usr/local/bin/
sudo install -m 0755 bin/tlsherd-agent /usr/local/bin/        # on every managed host
```

### 1. Docker Compose (server + PostgreSQL)

The compose file builds the server image and starts Postgres with the schema on first boot:

```sh
export TLSHERD_DB_PASSWORD='long-random-password'
# Lab default: plain HTTP. For HTTPS set TLSHERD_INSECURE_HTTP=0 and mount certs
# (see comments in deploy/docker-compose.yml).
docker compose -f deploy/docker-compose.yml up -d --build
```

Published ports (loopback by default; override with `TLSHERD_ADMIN_PORT` / `TLSHERD_AGENT_PORT`):

| Port | Purpose |
| --- | --- |
| `8443` | Admin UI + operator/admin JSON API |
| `8444` | Agent API only (`/api/v1/agent/*`) |

On first start the server creates the bootstrap admin and logs the temporary
password at WARN. Read it from compose logs:

```sh
docker compose -f deploy/docker-compose.yml logs server | grep -i bootstrap
```

Alternatively, use an existing PostgreSQL and a host-installed binary:

```sh
createdb tlsherd
export TLSHERD_DATABASE_URL='postgres://tlsherd:PASSWORD@127.0.0.1:5432/tlsherd?sslmode=disable'
make schema
```

`migrations/schema.sql` always describes the complete, from-scratch schema. For upgrades
of an existing database, apply the ordered `ALTER`/`UPDATE` statements delivered with the
release notes; do not re-run the schema file on a populated database.

### 2. First administrator

No separate bootstrap step is required for normal installs: starting
`tlsherd-server` against an empty database creates `admin` (override with
`TLSHERD_BOOTSTRAP_LOGIN`) and prints the temporary password once:

```text
level=WARN msg="bootstrap administrator created; change this password immediately after login" login=admin password=...
```

Sign in, then set a new password on the Account page (API blocks everything else
until `must_change_password` is cleared).

Create further users in the UI (Users page), then add operators to groups.

### 3. Server listeners and TLS

Configuration is read from `TLSHERD_*` variables (see `deploy/server.env`):

| Variable | Meaning |
| --- | --- |
| `TLSHERD_DATABASE_URL` | PostgreSQL connection string (required) |
| `TLSHERD_ADMIN_LISTEN` | admin UI/API listen address, default `:8443` |
| `TLSHERD_AGENT_LISTEN` | agent API listen address, default `:8444` (must differ from admin) |
| `TLSHERD_LISTEN` | legacy alias for admin listen if `TLSHERD_ADMIN_LISTEN` is unset |
| `TLSHERD_DATA_DIR` | certificate store, default `/var/lib/tlsherd` |
| `TLSHERD_TLS_CERT`, `TLSHERD_TLS_KEY` | server certificate and key for **both** listeners (required unless insecure) |
| `TLSHERD_INSECURE_HTTP=1` / `--insecure-http` | serve plain HTTP on both listeners |
| `TLSHERD_TRUST_PROXY=1` | client IP from the last `X-Forwarded-For` entry |
| `TLSHERD_BOOTSTRAP_LOGIN` | first-admin login when the users table is empty (default `admin`) |
| `TLSHERD_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |

- **Default (recommended): HTTPS.** Provide a certificate for the server's own name
  (it can be one of the domains managed by TLS herd itself, after the first upload).
  Cookies are marked `Secure`. The service user must be able to read the key file.
- **`--insecure-http`: plain HTTP.** Cookies are *not* `Secure`, so browsers send the
  session cookie over HTTP. Use it only (a) behind a reverse proxy that terminates TLS
  and is the only way to reach the port (bind to `127.0.0.1`, set
  `TLSHERD_TRUST_PROXY=1` only if the proxy sets `X-Forwarded-For`), or (b) in a lab.
  Note that with plain HTTP between proxy and server, the browser-facing cookies are still
  marked non-`Secure`; the proxy must enforce HTTPS and HSTS. Never expose the
  insecure listener to agents or operators directly.

Run it under systemd (instead of or in addition to compose):

```sh
sudo useradd --system --home /var/lib/tlsherd --shell /usr/sbin/nologin tlsherd
sudo install -d -m 0750 -o root -g tlsherd /etc/tlsherd
sudo install -m 0640 -o root -g tlsherd deploy/server.env /etc/tlsherd/server.env   # edit first
sudo install -m 0644 deploy/tlsherd-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tlsherd-server
curl -fsS https://tlsherd.example.com:8443/readyz   # admin
curl -fsS https://tlsherd.example.com:8444/readyz   # agent
```

Open `https://tlsherd.example.com:8443/` and sign in with the bootstrap admin.
Point agents at the **agent** listener (`TLSHERD_SERVER_URL=https://…:8444`).

### 4. Agents (systemd)

On every managed host:

```sh
sudo install -d -m 0755 /etc/tlsherd
sudo install -d -m 0700 /var/lib/tlsherd-agent
sudo install -m 0600 deploy/agent.env /etc/tlsherd/agent.env     # set TLSHERD_SERVER_URL, TLSHERD_CA_FILE
sudo install -m 0600 deploy/agent.local.cfg /var/lib/tlsherd-agent/agent.local.cfg  # edit service/paths
sudo install -m 0644 deploy/tlsherd-agent.service /etc/systemd/system/
# docker-managed services: use deploy/tlsherd-agent-docker.service instead
sudo systemctl daemon-reload && sudo systemctl enable --now tlsherd-agent
```

Typical first-run flow:

1. Agent enrolls and waits (`Enrollments` shows pending).
2. Admin **Accept** (optional display name / link existing server).
3. Create **Domain**, upload cert+key (or fullchain PEM as cert file).
4. Assign domain → server under **Domains → … → Servers & paths**.
5. Set **Servers → server → Agent local config** (or edit `agent.local.cfg` on the host).
6. Tune schedule under **Agent defaults** / per-server **Schedule configuration**.
7. Preview with `tlsherd-agent --once --dry-run` on the host.

## Configuration reference

Samples live under [`deploy/`](deploy/) (see [`deploy/README.md`](deploy/README.md)).

### Server environment (`deploy/server.env`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `TLSHERD_DATABASE_URL` | *(required)* | PostgreSQL URL |
| `TLSHERD_ADMIN_LISTEN` | `:8443` | Admin UI + JSON API |
| `TLSHERD_AGENT_LISTEN` | `:8444` | Agent API only (must differ) |
| `TLSHERD_LISTEN` | — | Legacy alias for admin listen |
| `TLSHERD_DATA_DIR` | `/var/lib/tlsherd` | Server PEM store (backup this) |
| `TLSHERD_TLS_CERT` / `TLSHERD_TLS_KEY` | — | HTTPS for both listeners |
| `TLSHERD_INSECURE_HTTP` | off | Plain HTTP (lab / TLS-terminating proxy) |
| `TLSHERD_TRUST_PROXY` | off | Client IP from last `X-Forwarded-For` |
| `TLSHERD_BOOTSTRAP_LOGIN` | `admin` | First admin login if users table empty |
| `TLSHERD_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

Flags: `--insecure-http` (same as env).

Compose extras: `TLSHERD_ADMIN_PORT` / `TLSHERD_AGENT_PORT` (published host ports),
`TLSHERD_DB_PASSWORD`.

### Notifications (admin UI / `system_settings.notifications`)

Configured in **Notifications** (SMTP, Telegram bot token, worker) and
**Notification accounts** (recipients). Not environment variables.

| Channel | Global setting | Per-account destination |
| --- | --- | --- |
| Email | SMTP host/port/user/password/from/TLS | `address` |
| Telegram | `bot_token` | `chat_id` |
| Webhook | — | `url`, optional `secret` (HMAC-SHA256 in `X-Tlsherd-Signature`) |

Notify on **new open** and on **resolve/dismiss** (with duration). Dedup refresh of an
already-open event does not re-notify. Working-hours window defers delivery; it does
not drop the message. Default event types for a new account:
`cert_expired`, `cert_expiring_soon`, `cert_key_mismatch`, `cert_chain_invalid`,
`cert_domain_mismatch_confirmed`, `endpoint_cert_mismatch`.

### Agent environment (`deploy/agent.env`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `TLSHERD_SERVER_URL` | *(required)* | Base URL of the **agent** listener (`…:8444`) |
| `TLSHERD_CERT_ROOT` | `/etc/tls` | Host cert tree: `<root>/<fqdn>/{current,versions,backups}` |
| `TLSHERD_AGENT_DIR` | `/var/lib/tlsherd-agent` | Agent home: `state.json`, `config.cfg`(+`.prev`), `agent.local.cfg`(+`.prev`) |
| `TLSHERD_CA_FILE` | — | Extra CA PEM to trust the server certificate |
| `TLSHERD_LOG_LEVEL` | `info` | Log level |

CLI flags:

| Flag | Meaning |
| --- | --- |
| `--once` | One enroll/poll cycle, then exit |
| `--dry-run` | Plan only: no file/state/service changes |
| `--insecure-skip-verify` | Skip server TLS verify (**lab only**) |

### Agent local config (`agent.local.cfg`)

JSON document on the **agent host**. Priority for service identity, pre-start check,
restart, and install paths. Reported to the server on enroll/poll. Server UI
**Servers → Agent local config → Save & push** queues an update; on the next poll the
agent rotates the active file to `agent.local.cfg.prev` (one previous version) and
writes the new file, then reloads in-process.

If the active file is missing/corrupt, the agent loads `.prev` (WARN) or empty
`custom` defaults.

#### Top-level fields

| Field | Meaning |
| --- | --- |
| `service` | Catalog id: `nginx`, `haproxy`, `apache2`, `httpd`, or `custom` |
| `verify` | Pre-start check run after files are switched, **before** restart |
| `restart` | How to reload/restart the local web (or other) service |
| `install` | How files appear under the cert root |
| `cert_root` | Working cert directory (overrides `TLSHERD_CERT_ROOT`, default `/etc/tls`) |
| `cert_path` / `key_path` / `chain_path` | Optional extra publish paths for leaf / key / intermediates (`{domain}` ok) |
| `fullchain_path` | Optional extra publish of **leaf+chain** (use this for nginx `ssl_certificate`) |

#### Service catalog defaults

Selecting a service in the UI (or starting from the sample file) fills verify/restart:

| `service` | Default verify argv | Default restart |
| --- | --- | --- |
| `nginx` | `nginx -t` | systemd unit `nginx`, reload |
| `haproxy` | `haproxy -f /etc/haproxy/haproxy.cfg -c` | systemd `haproxy`, reload |
| `apache2` | `apache2ctl configtest` | systemd `apache2`, reload |
| `httpd` | `httpd -t` | systemd `httpd`, reload |
| `custom` | *(empty — disabled)* | systemd (you must set `name` / commands) |

Any field remains editable after choosing a catalog entry.

#### `verify` (pre-start check)

| Field | Meaning |
| --- | --- |
| `command` | Argv list (no shell). Empty = skip verify |
| `timeout` | Go duration string, e.g. `"30s"` |

On failure the agent **restores the previous files** and does **not** restart.

#### `restart`

| Field | Meaning |
| --- | --- |
| `type` | `systemd` \| `docker` \| `exec` |
| `name` | systemd unit or Docker container name |
| `reload_only` | Prefer reload over full restart when supported |
| `command` | Argv for `type=exec`, or for docker reload (`docker exec <name> …`) |

What the agent runs:

| `type` | Behavior |
| --- | --- |
| `systemd` | `systemctl reload\|restart <name>` (`reload` if `reload_only`) |
| `docker` | `docker restart <name>`, or with `reload_only` + `command`: `docker exec <name> …` |
| `exec` | Runs `command` as argv (paths may include `{domain}`) |

Use `deploy/tlsherd-agent-docker.service` when `type=docker` (needs `docker.sock`).

#### `install`

On-disk layout under cert root (default `/etc/tls`):

```text
<cert_root>/<fqdn>/
  versions/<fingerprint>/{cert,key,chain,fullchain}.pem
  current/   → versions/<fingerprint>/          # or a real directory in copy mode
  backups/<timestamp>/                          # pre-apply snapshot
```

| Field | Meaning |
| --- | --- |
| `mode` | `symlink` (default) or `copy` — see below |
| `cert_name` / `key_name` / `chain_name` / `fullchain_name` | Filenames inside `versions/` and `current/` |
| `subdir` | Optional subdirectory under the domain tree |
| `owner` | Optional `user[:group]` after write |
| `dir_mode` / `key_mode` / `cert_mode` | Octal permission strings (`0750`, `0600`, `0644`) |

`fullchain.pem` is always written (leaf, or leaf+intermediates). Nginx should use fullchain
(or `fullchain_path`), not leaf alone.

**`mode: symlink`** — write PEMs once under `versions/<fp>/`, point `current` (and optional
extra paths) at them with symlinks.

**`mode: copy`** — same version store, but `current/` is a real directory of copied files
(extra paths are copied too). Use when the consumer cannot follow symlinks.

**Nginx example** (`cert_root=/cert`, `fullchain_path={domain}.crt`, `key_path={domain}.key`):

```nginx
ssl_certificate     /cert/a-mobile.biz.crt;   # fullchain published by agent
ssl_certificate_key /cert/a-mobile.biz.key;
```

Domain assignment paths / `restart_override` from the UI still apply as a **last overlay**
for that domain only.

### Schedule config (server → `config.cfg`)

Edited in **Agent defaults** (all agents without a custom doc) or
**Servers → Schedule configuration** (per-server custom document; **Force from defaults**
copies defaults into a custom doc). Agents store it as `config.cfg` (+ `.prev`).

These fields stay server-authoritative (local config does **not** own them):

| Field | Meaning | Typical default |
| --- | --- | --- |
| `enroll_interval` | How often a not-yet-accepted agent retries enroll | `1m` |
| `poll_interval` | How often an accepted agent polls | `12h` |
| `jitter` | ± fraction applied to intervals (`0`–`1`) | `0.1` |
| `maintenance_window` | `tz`, `days` (1=Mon…7=Sun), `from`/`to` (`HH:MM`) | UTC nightly window |
| `urgent_threshold` | Apply outside the window if installed cert expires sooner | `72h` |
| `stage_outside_window` | Download/stage new certs outside the window without activating | `true` |
| `strict_cert_check` | Refuse install/reload when cert is expired, not yet valid, or critically broken | `true` |
| `post_check` | After restart, dial `addr` with optional `sni` and compare fingerprint | off |
| `backups.keep` | How many agent-side backup snapshots to retain | `5` |

Note: schedule documents may still contain `install` / `verify` / `restart` keys for
backward compatibility; when `agent.local.cfg` is configured, those local fields win at
apply time.

### Config merge order (apply)

1. Built-in defaults → stored schedule document (`agent_defaults` or per-server `server_configs`).
2. Overlay **agent local config** (service verify/restart/install/paths) when configured.
3. Overlay non-empty **domain assignment** `install_mode`, paths, `restart_override`.

### Operator workflow cheat sheet

| Task | Where |
| --- | --- |
| First admin password | Server logs (WARN) → Account page |
| Accept agent | **Enrollments** |
| Domain without group | **Domains** (groups optional; assign later) |
| Upload cert | Domain page; cert file may be leaf-only or fullchain |
| Host nginx/haproxy/… | **Servers → Agent local config** or edit `agent.local.cfg` |
| Poll / maintenance window | **Agent defaults** or per-server schedule config |
| Clear a stuck event | **Events → Dismiss** (events do not auto-expire) |
| Preview agent actions | `tlsherd-agent --once --dry-run` on the host |

## Runbooks

### Backup

Back up both parts together; they reference each other.

```sh
# 1. database
pg_dump --format=custom --file=tlsherd-$(date +%F).dump "$TLSHERD_DATABASE_URL"
# 2. certificate store (contains private keys: encrypt the archive)
sudo tar --create --gzip --file=tlsherd-data-$(date +%F).tar.gz -C /var/lib/tlsherd .
```

Take them while the server is idle or stopped for a consistent pair; certificate files are
immutable and only added, so a data-dir copy that is *newer* than the database is safe. Also
keep `/etc/tlsherd/server.env` and the server TLS key in your secret store. Agents need no
backup: they re-enroll (a new key is issued after approval).

### Restore

1. Stop `tlsherd-server`.
2. Recreate an empty database and restore: `pg_restore --clean --if-exists --dbname="$TLSHERD_DATABASE_URL" tlsherd-YYYY-MM-DD.dump`
   (or `createdb` + `pg_restore --dbname=...` for a fresh instance).
3. Restore the data dir: `sudo tar --extract --gzip --file=tlsherd-data-….tar.gz -C /var/lib/tlsherd && sudo chown -R tlsherd:tlsherd /var/lib/tlsherd`.
4. Start the server and check `/readyz`, **Domains** (current versions present) and
   **Events**. Agents keep working if their IP and key are unchanged; otherwise they appear in
   the enrollment queue as identity changes: accept them *linking the existing server*.

### Rollback

*Bad certificate deployed (wrong cert, failed verify on hosts):*

1. **Domains → domain → Versions → Roll back** on the last known good version and give a reason
   (or `POST /api/v1/domains/{id}/rollback {"version": N, "reason": "..."}`).
2. Agents pick the old version up on their next poll (`poll_interval`; default 12 h). To speed
   up, lower `poll_interval` in the agent config, or restart `tlsherd-agent` on the hosts. Outside the
   maintenance window the agent only stages the files unless the installed certificate is within
   `urgent_threshold` of expiry.
3. Watch **Events** (`agent_apply_failed`, `agent_verify_failed`, `agent_post_check_mismatch`) and
   **Monitor → Check now** to confirm that endpoints serve the expected fingerprint.

*Agent-side failure:* the agent snapshots the active files before every install, and automatically
restores them when install, verify or restart fails, then reports the failure (check the details
of the event). Manual recovery on a host: `<cert_root>/<fqdn>/backups/<timestamp>/` holds the previous
files and `<cert_root>/<fqdn>/versions/<fingerprint>/` every installed version; point `current` back
and restart the service.

*Bad schedule config:* in **Servers → server → Schedule configuration** use **Force from defaults**
(with confirmation), or fix **Agent defaults**. Agents adopt the new document on the next poll;
previous schedule is `config.cfg.prev` under `TLSHERD_AGENT_DIR`.

*Bad local service config:* edit **Servers → Agent local config** and push, or fix
`$TLSHERD_AGENT_DIR/agent.local.cfg` on the host (default `/var/lib/tlsherd-agent/agent.local.cfg`).
The previous push is `agent.local.cfg.prev` (copy it back over the active file and restart the agent).

*Compromised agent key or host:* **Servers → server → Revoke all keys** (or **Rotate agent key**),
then delete the server if the host is gone. Rotate the certificates that host could read.

## Development

```sh
make check                      # go vet + go test ./...
go build ./cmd/... ./internal/...
make run-server                 # needs TLSHERD_* variables; use --insecure-http locally
```
