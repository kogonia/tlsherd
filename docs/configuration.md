# Server configuration

Samples live under [`deploy/`](../deploy/) (see [`deploy/README.md`](../deploy/README.md)).
Agent host config is documented in [Agent guide](agent.md).

## Server environment (`deploy/server.env`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `TLSHERD_DATABASE_URL` | *(required)* | PostgreSQL URL |
| `TLSHERD_ADMIN_LISTEN` | `:8443` | Admin UI + JSON API |
| `TLSHERD_AGENT_LISTEN` | `:8444` | Agent API only (must differ from admin) |
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

Admin and agent APIs use **separate TCP listeners** so firewalls can expose only the
agent port to managed hosts while keeping the UI/API on a private network.

## Notifications

Configured in the UI (**Notifications** for SMTP/Telegram/worker;
**Notification accounts** for recipients). Not environment variables.

| Channel | Global setting | Per-account destination |
| --- | --- | --- |
| Email | SMTP host/port/user/password/from/TLS | `address` |
| Telegram | `bot_token` | `chat_id` |
| Webhook | — | `url`, optional `secret` (HMAC-SHA256 in `X-Tlsherd-Signature`) |

Notify on **new open** and on **resolve/dismiss** (with duration). Dedup refresh of an
already-open event does not re-notify. Working-hours window defers delivery; it does
not drop the message.

Default event types for a new account: `cert_expired`, `cert_expiring_soon`,
`cert_key_mismatch`, `cert_chain_invalid`, `cert_domain_mismatch_confirmed`,
`endpoint_cert_mismatch`.

Stored under `system_settings.notifications` and related notification tables
(see `migrations/schema.sql`).
