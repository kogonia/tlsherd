# Agent guide

The **tlsherd-agent** runs on each managed host. It enrolls with the server, polls
for assigned certificates, installs them under a cert root, runs **pre-start
validation**, **restarts/reloads** the local web stack, optionally runs a
**post-check** (from schedule config), and reports the result.

Related samples: [`deploy/agent.env`](../deploy/agent.env),
[`deploy/agent.local.cfg`](../deploy/agent.local.cfg),
[`deploy/tlsherd-agent.service`](../deploy/tlsherd-agent.service),
[`deploy/tlsherd-agent-docker.service`](../deploy/tlsherd-agent-docker.service).

## Quick install (systemd)

```sh
sudo install -d -m 0755 /etc/tlsherd
sudo install -d -m 0700 /var/lib/tlsherd-agent
sudo install -m 0600 deploy/agent.env /etc/tlsherd/agent.env     # set TLSHERD_SERVER_URL, TLSHERD_CA_FILE
sudo install -m 0600 deploy/agent.local.cfg /var/lib/tlsherd-agent/agent.local.cfg  # edit web service / paths
sudo install -m 0644 deploy/tlsherd-agent.service /etc/systemd/system/
# If restart.type=docker: use deploy/tlsherd-agent-docker.service (needs docker.sock)
sudo systemctl daemon-reload && sudo systemctl enable --now tlsherd-agent
```

Typical first-run flow:

1. Agent enrolls → appears under **Enrollments** (pending).
2. Admin **Accept** (optional display name / link existing server).
3. Create **Domain**, upload cert+key (or fullchain PEM as cert file).
4. Assign domain → server under **Domains → … → Servers & paths**.
5. Set **Servers → Agent local config** (or edit `agent.local.cfg` on the host).
6. Tune schedule under **Agent defaults** / per-server **Schedule configuration**.
7. Preview with `tlsherd-agent --once --dry-run` on the host.

## Files on the host

| Path (defaults) | Role |
| --- | --- |
| `$TLSHERD_AGENT_DIR/state.json` | Enrollment/API key state |
| `$TLSHERD_AGENT_DIR/agent.local.cfg` | **Local** config: web service, pre-start, start method, install/paths (agent priority) |
| `$TLSHERD_AGENT_DIR/agent.local.cfg.prev` | Previous local config (one generation) |
| `$TLSHERD_AGENT_DIR/config.cfg` | **Schedule** config from the server (poll/window/backups/post_check) |
| `$TLSHERD_AGENT_DIR/config.cfg.prev` | Previous schedule document |
| `$TLSHERD_CERT_ROOT/<fqdn>/…` | Installed certificates (versions, current, backups) |

Defaults: `TLSHERD_AGENT_DIR=/var/lib/tlsherd-agent`, `TLSHERD_CERT_ROOT=/etc/tls`.

## Environment and CLI

| Variable | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `TLSHERD_SERVER_URL` | `-s` | *(required)* | Base URL of the **agent** listener (e.g. `https://tlsherd.example.com:8444`) |
| `TLSHERD_CERT_ROOT` | `-d` | `/etc/tls` | Host cert tree: `<root>/<fqdn>/{current,versions,backups}` |
| `TLSHERD_AGENT_DIR` | `-a` | `/var/lib/tlsherd-agent` | Agent home (state + both config files) |
| `TLSHERD_LOG_LEVEL` | `-l` | `info` | `debug` / `info` / `warn` / `error` |
| `TLSHERD_CA_FILE` | — | — | Extra CA PEM to trust the server certificate |

Flags override the matching environment variable when set.

| Flag | Meaning |
| --- | --- |
| `--once` | One enroll/poll cycle, then exit |
| `--dry-run` | Plan only: no file/state/service changes |
| `--insecure-skip-verify` | Skip server TLS verify (**lab only**) |

```sh
tlsherd-agent -s https://tlsherd.example.com:8444 -d /cert -a /var/lib/tlsherd-agent -l debug --once --dry-run
```

## Two config layers

| Layer | File | Owns | Who wins |
| --- | --- | --- | --- |
| **Local** | `agent.local.cfg` | Web service, pre-start (`verify`), start method (`restart`), install & paths | Agent / host (server UI can push) |
| **Schedule** | `config.cfg` | Poll/enroll intervals, maintenance window, backups, `post_check`, `strict_cert_check` | Server (defaults or per-server doc) |

Apply merge order:

1. Built-in defaults → stored schedule document.
2. Overlay **local** config when configured.
3. Overlay non-empty **domain assignment** paths / `restart_override`.

---

## Local config (`agent.local.cfg`)

JSON on the agent host. Reported to the server on enroll/poll. **Servers → Agent
local config → Save & push** queues an update; on the next poll the agent rotates
the active file to `.prev` and writes the new document, then reloads in-process.

If the active file is missing/corrupt, the agent loads `.prev` (WARN) or empty
`custom` defaults.

### Top-level fields

| Field | UI label | Meaning |
| --- | --- | --- |
| `service` | **Web service** | Catalog id: `nginx`, `haproxy`, `apache2`, `httpd`, `custom` |
| `verify` | **Pre-start (validation)** | Check after files are switched, **before** restart |
| `restart` | **Start method** + restart/reload | `restart.type` = `systemd` \| `docker` \| `exec` |
| `install` | Install & paths | Layout under cert root |
| `cert_root` | Cert root | Overrides `TLSHERD_CERT_ROOT` |
| `cert_path` / `key_path` / `chain_path` | Extra publish paths | Leaf / key / intermediates (`{domain}` ok) |
| `fullchain_path` | Extra fullchain path | Leaf+chain (use for nginx `ssl_certificate`) |
| `strict_cert_check` | (optional) | Overrides schedule `strict_cert_check` when set |

### Web service × start method

The UI picks a **web service** and a **start method**. Together they fill
`verify` and `restart` (all fields remain editable afterward).

| Web (`service`) | Base verify | Soft reload argv |
| --- | --- | --- |
| `nginx` | `nginx -t` | `nginx -s reload` |
| `haproxy` | `haproxy -f /etc/haproxy/haproxy.cfg -c` | `kill -USR2 1` |
| `apache2` | `apache2ctl configtest` | `apache2ctl graceful` |
| `httpd` | `httpd -t` | `httpd -k graceful` |
| `custom` | *(empty)* | *(empty)* |

| Start method (`restart.type`) | Pre-start becomes | Restart becomes |
| --- | --- | --- |
| `systemd` | base verify | `systemctl reload\|restart <name>` |
| `docker` | `docker exec <name> …base verify` | `docker restart <name>`, or with reload: `docker exec <name> …reload` |
| `exec` (UI: **Custom command**) | base verify | runs `restart.command` as argv |

Legacy: verify left as `nginx -t` with `restart.type=docker` still works — the agent
prefixes `docker exec <name>` at runtime.

### `verify` — pre-start (validation)

| Field | Meaning |
| --- | --- |
| `command` | Argv list (**no shell**). Empty = skip |
| `timeout` | Go duration, e.g. `"30s"` |

On failure the agent **restores the previous files** and does **not** restart.

### `restart` — start method

| Field | Meaning |
| --- | --- |
| `type` | `systemd` \| `docker` \| `exec` |
| `name` | systemd unit or Docker container name |
| `reload_only` | Prefer reload over full restart when supported |
| `command` | Argv for `type=exec`, or docker reload payload (`docker exec <name> …`) |

| `type` | What the agent runs |
| --- | --- |
| `systemd` | `systemctl reload\|restart <name>` (`reload` if `reload_only`) |
| `docker` | `docker restart <name>`, or with `reload_only` + `command`: `docker exec <name> …` |
| `exec` | Runs `command` as argv (`{domain}` expanded in path-like args) |

Use `deploy/tlsherd-agent-docker.service` when `type=docker` (needs `docker.sock`).

### `install`

On-disk layout under cert root (default `/etc/tls`):

```text
<cert_root>/<fqdn>/
  versions/<fingerprint>/{cert,key,chain,fullchain}.pem
  current/   → versions/<fingerprint>/          # or a real directory in copy mode
  backups/<timestamp>/                          # pre-apply snapshot
```

| Field | Meaning |
| --- | --- |
| `mode` | `symlink` (default) or `copy` |
| `cert_name` / `key_name` / `chain_name` / `fullchain_name` | Filenames inside `versions/` and `current/` |
| `subdir` | Optional subdirectory under the domain tree |
| `owner` | Optional `user[:group]` after write |
| `dir_mode` / `key_mode` / `cert_mode` | Octal permission strings |

`fullchain.pem` is always written (leaf, or leaf+intermediates). Nginx should use
fullchain (or `fullchain_path`), not leaf alone.

**`mode: symlink`** — write PEMs under `versions/<fp>/`, point `current` (and optional
extra paths) with symlinks.

**`mode: copy`** — same version store, but `current/` is a real directory of copied
files (use when the consumer cannot follow symlinks).

Domain assignment paths / `restart_override` from the UI still apply as a **last
overlay** for that domain only.

---

## Full examples

### nginx + systemd (sample `deploy/agent.local.cfg`)

```json
{
  "service": "nginx",
  "cert_root": "/cert",
  "fullchain_path": "{domain}.crt",
  "key_path": "{domain}.key",
  "verify": {
    "command": ["nginx", "-t"],
    "timeout": "30s"
  },
  "restart": {
    "type": "systemd",
    "name": "nginx",
    "reload_only": true
  },
  "install": {
    "mode": "symlink",
    "cert_name": "cert.pem",
    "key_name": "key.pem",
    "chain_name": "chain.pem",
    "fullchain_name": "fullchain.pem",
    "dir_mode": "0750",
    "key_mode": "0600",
    "cert_mode": "0644"
  }
}
```

Agent runs:

1. Pre-start: `nginx -t`
2. Restart: `systemctl reload nginx`

Nginx:

```nginx
ssl_certificate     /cert/example.com.crt;   # fullchain published by agent
ssl_certificate_key /cert/example.com.key;
```

### nginx + docker

Container name `web`, soft reload inside the container:

```json
{
  "service": "nginx",
  "cert_root": "/cert",
  "fullchain_path": "{domain}.crt",
  "key_path": "{domain}.key",
  "verify": {
    "command": ["docker", "exec", "web", "nginx", "-t"],
    "timeout": "30s"
  },
  "restart": {
    "type": "docker",
    "name": "web",
    "reload_only": true,
    "command": ["nginx", "-s", "reload"]
  },
  "install": {
    "mode": "symlink",
    "cert_name": "cert.pem",
    "key_name": "key.pem",
    "chain_name": "chain.pem",
    "fullchain_name": "fullchain.pem",
    "dir_mode": "0750",
    "key_mode": "0600",
    "cert_mode": "0644"
  }
}
```

Agent runs:

1. Pre-start: `docker exec web nginx -t`
2. Restart: `docker exec web nginx -s reload`

With `"reload_only": false` (and no need for `command`), restart becomes
`docker restart web`.

Mount/publish cert paths into the container so nginx inside sees the same files
the agent wrote under `cert_root`.

### Custom command (`restart.type=exec`)

```json
{
  "service": "custom",
  "verify": {
    "command": ["/usr/local/bin/check-certs", "{domain}"],
    "timeout": "30s"
  },
  "restart": {
    "type": "exec",
    "command": ["/usr/local/bin/reload-tls", "{domain}"]
  },
  "install": {
    "mode": "copy",
    "cert_name": "cert.pem",
    "key_name": "key.pem",
    "chain_name": "chain.pem",
    "fullchain_name": "fullchain.pem",
    "dir_mode": "0750",
    "key_mode": "0600",
    "cert_mode": "0644"
  }
}
```

---

## Schedule config (server → `config.cfg`)

Edited in **Agent defaults** (all agents without a custom doc) or
**Servers → Schedule configuration** (per-server; **Force from defaults** copies
defaults into a custom doc). Agents store it as `config.cfg` (+ `.prev`).

Local config does **not** own these fields:

| Field | Meaning | Typical default |
| --- | --- | --- |
| `enroll_interval` | How often a not-yet-accepted agent retries enroll | `1m` |
| `poll_interval` | How often an accepted agent polls | `12h` |
| `jitter` | ± fraction applied to intervals (`0`–`1`) | `0.1` |
| `maintenance_window` | `tz`, `days` (1=Mon…7=Sun), `from`/`to` (`HH:MM`; equal = all day) | UTC all day |
| `urgent_threshold` | Apply outside the window if installed cert expires sooner | `72h` |
| `stage_outside_window` | Download/stage new certs outside the window without activating | `true` |
| `strict_cert_check` | Refuse install/reload when cert is expired, not yet valid, or critically broken | `true` |
| `post_check` | After restart, dial `addr` with optional `sni` and compare fingerprint | off |
| `backups.keep` | How many agent-side backup snapshots to retain | `5` |

Schedule documents may still contain legacy `install` / `verify` / `restart` keys;
when `agent.local.cfg` is configured, those local fields win at apply time.

**Post-check** (schedule) is the existing “after restart, dial and compare fingerprint”
step — distinct from a future in-process post-start command, if added later.

### Example schedule snippet

```json
{
  "poll_interval": "12h",
  "jitter": 0.1,
  "maintenance_window": {
    "tz": "Europe/Berlin",
    "days": [1, 2, 3, 4, 5],
    "from": "02:00",
    "to": "05:00"
  },
  "urgent_threshold": "72h",
  "stage_outside_window": true,
  "strict_cert_check": true,
  "post_check": {
    "addr": "127.0.0.1:443",
    "sni": "example.com"
  },
  "backups": { "keep": 5 }
}
```

---

## Security notes

The agent runs pre-start and restart commands **as the unit user** (typically root).
Anyone who can edit `agent.local.cfg` (on the host or via the server UI push) can
run arbitrary argv on that host. Commands are argv lists, never a shell; certificate
paths stay under the cert root.

See the [threat model](../README.md#threat-model) in the main README.
