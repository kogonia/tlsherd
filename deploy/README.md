# Deploy samples

| File | Install as | Purpose |
| --- | --- | --- |
| `server.env` | `/etc/tlsherd/server.env` (0600) | `tlsherd-server` environment |
| `tlsherd-server.service` | systemd unit | server |
| `agent.env` | `/etc/tlsherd/agent.env` (0600) | `tlsherd-agent` environment |
| `agent.local.cfg` | `/var/lib/tlsherd-agent/agent.local.cfg` (0600) | web service / pre-start / start method / install |
| `tlsherd-agent.service` | systemd unit | agent (systemd start method) |
| `tlsherd-agent-docker.service` | systemd unit | agent with `docker.sock` for `restart.type=docker` |
| `docker-compose.yml` | — | server + PostgreSQL |
| `docker-compose-override.yml` | — | local/dev overrides |

Documentation:

- Project overview: [../README.md](../README.md)
- Agent local + schedule config and examples: [../docs/agent.md](../docs/agent.md)
- Server env + notifications: [../docs/configuration.md](../docs/configuration.md)
- Backup / restore / rollback: [../docs/operations.md](../docs/operations.md)

Notification channels (SMTP / Telegram / webhook) and recipients are configured in the
admin UI (**Notifications**, **Notification accounts**), not in env files.

Sample [`agent.local.cfg`](agent.local.cfg) is **nginx + systemd**: `cert_root=/cert`,
publishes fullchain to `{domain}.crt` and key to `{domain}.key`. For docker / custom
command examples see the [Agent guide](../docs/agent.md#full-examples).
