# Operations runbooks

## Backup

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

## Restore

1. Stop `tlsherd-server`.
2. Recreate an empty database and restore: `pg_restore --clean --if-exists --dbname="$TLSHERD_DATABASE_URL" tlsherd-YYYY-MM-DD.dump`
   (or `createdb` + `pg_restore --dbname=...` for a fresh instance).
3. Restore the data dir: `sudo tar --extract --gzip --file=tlsherd-data-….tar.gz -C /var/lib/tlsherd && sudo chown -R tlsherd:tlsherd /var/lib/tlsherd`.
4. Start the server and check `/readyz`, **Domains** (current versions present) and
   **Events**. Agents keep working if their IP and key are unchanged; otherwise they appear in
   the enrollment queue as identity changes: accept them *linking the existing server*.

## Rollback

### Bad certificate deployed

1. **Domains → domain → Versions → Roll back** on the last known good version and give a reason
   (or `POST /api/v1/domains/{id}/rollback {"version": N, "reason": "..."}`).
2. Agents pick the old version up on their next poll (`poll_interval`; default 12 h). To speed
   up, lower `poll_interval` in the agent schedule config, or restart `tlsherd-agent` on the hosts.
   Outside the maintenance window the agent only stages the files unless the installed
   certificate is within `urgent_threshold` of expiry.
3. Watch **Events** (`agent_apply_failed`, `agent_verify_failed`, `agent_post_check_mismatch`) and
   **Monitor → Check now** to confirm that endpoints serve the expected fingerprint.

### Agent-side failure

The agent snapshots the active files before every install, and automatically restores them when
install, pre-start validation, or restart fails, then reports the failure (check the event
details). Manual recovery on a host: `<cert_root>/<fqdn>/backups/<timestamp>/` holds the previous
files and `<cert_root>/<fqdn>/versions/<fingerprint>/` every installed version; point `current`
back and reload the service.

### Bad schedule config

In **Servers → Schedule configuration** use **Force from defaults** (with confirmation), or fix
**Agent defaults**. Agents adopt the new document on the next poll; previous schedule is
`config.cfg.prev` under `TLSHERD_AGENT_DIR`.

### Bad local service config

Edit **Servers → Agent local config** and save for the agent to pull, or fix
`$TLSHERD_AGENT_DIR/agent.local.cfg` on the host (default `/var/lib/tlsherd-agent/agent.local.cfg`).
The previous file is `agent.local.cfg.prev` (copy it back over the active file and
restart the agent).

### Compromised agent key or host

**Servers → server → Revoke all keys** (or **Rotate agent key**), then delete the server if the
host is gone. Rotate the certificates that host could read.

## Operator cheat sheet

| Task | Where |
| --- | --- |
| First admin password | Server logs (WARN) → Account page |
| Accept agent | **Enrollments** |
| Domain without group | **Domains** (groups optional; assign later) |
| Upload cert | Domain page; cert file may be leaf-only or fullchain |
| Host nginx/haproxy/… | **Servers → Agent local config** or edit `agent.local.cfg` — see [Agent guide](agent.md) |
| Poll / maintenance window | **Agent defaults** or per-server schedule config |
| Clear a stuck event | **Events → Dismiss** (events do not auto-expire) |
| Preview agent actions | `tlsherd-agent --once --dry-run` on the host |
