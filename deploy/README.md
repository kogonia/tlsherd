# Deploy samples

| File | Install as | Purpose |
| --- | --- | --- |
| `server.env` | `/etc/tlsherd/server.env` (0600) | `tlsherd-server` environment |
| `tlsherd-server.service` | systemd unit | server |
| `agent.env` | `/etc/tlsherd/agent.env` (0600) | `tlsherd-agent` environment |
| `agent.local.cfg` | `/var/lib/tlsherd-agent/agent.local.cfg` (0600) | host service / verify / restart / install |
| `tlsherd-agent.service` | systemd unit | agent (systemd restart of local services) |
| `tlsherd-agent-docker.service` | systemd unit | agent with `docker.sock` for `restart.type=docker` |
| `docker-compose.yml` | — | server + PostgreSQL |
| `docker-compose-override.yml` | — | local/dev overrides |

Operator documentation (fields, merge order, layouts): see the root [README.md](../README.md) sections **Configuration reference** and **Deploy**.

Notification channels (SMTP / Telegram / webhook) and recipients are configured in the
admin UI (**Notifications**, **Notification accounts**), not in env files.

Sample [`agent.local.cfg`](agent.local.cfg) uses `cert_root=/cert`, publishes nginx-ready
fullchain to `{domain}.crt` and key to `{domain}.key` (no manual concat).
