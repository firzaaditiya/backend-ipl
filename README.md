# FIM-IPL Backend

Go-based File Integrity Monitoring daemon and REST API for FIM-IPL. The
backend compares SHA-256 file hashes against a baseline, records changes in a
local append-only hash-chained Immutable Private Ledger, quarantines suspicious
files, and publishes operational alerts through Telegram.

## Features

- Polling scanner using `filepath.Walk`, a worker pool, and SHA-256.
- Detection of `CREATED`, `MODIFIED`, `DELETED`, and `UNREADABLE` files.
- Automatic quarantine with platform-aware behavior:
  - Linux: `chmod 000`.
  - Windows: best-effort ReadOnly attribute; official performance evidence is
    taken on Linux/VPS.
- Append-only Bbolt ledger with hash-chain verification and external head
  anchor support.
- Telegram alerts, ledger backups, retry for transient network/429/5xx errors,
  and token redaction in errors.
- JWT authentication, bcrypt passwords, Super Admin/Auditor RBAC, rate limit,
  CORS allowlist, security headers, SSE events, and SSRF-safe webhook checks.
- Environment overrides for secrets so credentials are not written back to
  `config.json`.

## Requirements

- Go 1.25+.
- Linux is recommended for production. Windows is supported for local demo and
  functional testing.
- A readable watch directory and a writable private data directory.

## Local Run

Copy the example configuration and set secrets through environment variables:

```bash
cp data/config.example.json data/config.json
export FIM_CONFIG_PATH="$PWD/data/config.json"
export FIM_JWT_SECRET="replace-with-at-least-32-random-characters"
export FIM_ADMIN_PASSWORD="replace-with-a-strong-password"
go run ./cmd/server
```

Health check:

```bash
curl http://127.0.0.1:8080/api/v1/healthz
```

On Windows PowerShell, use `$env:FIM_*` equivalents. Do not commit
`data/config.json`, database files, tokens, passwords, or webhook credentials.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `FIM_CONFIG_PATH` | Configuration file location |
| `FIM_SERVER_PORT` | API listen address/port override |
| `FIM_DB_PATH` | Bbolt database location override |
| `FIM_JWT_SECRET` | JWT signing secret, minimum 32 characters |
| `FIM_ADMIN_USERNAME` | Super Admin username override |
| `FIM_ADMIN_PASSWORD` | Super Admin password override |
| `FIM_AUDITOR_USERNAME` | Auditor username override |
| `FIM_AUDITOR_PASSWORD` | Auditor password override |
| `FIM_TELEGRAM_TOKEN` | Telegram bot token |
| `FIM_TELEGRAM_CHAT_ID` | Telegram destination |
| `FIM_ALLOWED_ORIGINS` | Comma-separated CORS origins |
| `FIM_STRICT_SECRETS` | Set to `1` to fail startup for weak JWT secrets |

## API Overview

The API is mounted below `/api/v1`.

- `GET /healthz` - public liveness check.
- `POST /secure-gate` - login and JWT issuance.
- `GET /dashboard/stats` - current baseline, anomaly, and quarantine summary.
- `GET /ledger/blocks` - paginated and filterable audit blocks.
- `GET /ledger/verify` - verify the complete hash chain.
- `GET /ledger/export` - export ledger JSON for off-host backup.
- `GET /metrics` - scan performance metrics.
- `GET /events` - authenticated realtime SSE stream.
- `POST /baseline/init` and `/baseline/update` - Super Admin only.
- `POST /monitoring/start` and `/monitoring/stop` - Super Admin only.
- `POST /maintenance/enable` and `/maintenance/disable` - Super Admin only.
- `POST /quarantine/release` - audited quarantine release.
- `POST /backup/run` - manual ledger backup.

See `internal/api/router.go` for the complete route wiring.

## Production Deployment

Use `deploy/fim-ipl.service` as the systemd template. Run the daemon as a
dedicated `fim-ipl` user, never as `www-data` or the web application user.
Keep `/etc/fim-ipl/fim.env` owned by `root:root` with mode `0600`, use
`FIM_STRICT_SECRETS=1`, and keep the ledger/config directory inaccessible to
the web user. The daemon only needs read access to the monitored web root.

Example secret file:

```text
FIM_STRICT_SECRETS=1
FIM_JWT_SECRET=replace-with-a-random-secret
FIM_ADMIN_PASSWORD=replace-with-a-strong-password
FIM_TELEGRAM_TOKEN=replace-with-a-new-token
FIM_TELEGRAM_CHAT_ID=replace-with-a-chat-id
```

If the web application and the FIM daemon run as the same OS user, a web
compromise can read the daemon's secrets and ledger. Separate OS identities
are therefore a security requirement, not an optional optimization.

### Web compromise threat model

If an attacker uploads a file manager or obtains a remote shell as `www-data`,
assume they can read everything owned/readable by `www-data`. There is no
reliable "hidden config" technique that defeats a user who already has those
permissions. The deployment boundary must therefore be:

- Web files are readable by the FIM user, but `/opt/fim-ipl/data` is not
  readable by `www-data`.
- Secrets are loaded from `/etc/fim-ipl/fim.env` or systemd credentials, not
  from the project directory or webroot.
- `FIM_REQUIRE_EXTERNAL_SECRETS=1` rejects credentials in `config.json`.
- `FIM_REQUIRE_LOCAL_API=1` rejects wildcard API binding. Put Nginx/Caddy in
  front if remote operator access is needed.
- `ProtectProc=invisible`, `NoNewPrivileges`, and the dedicated systemd user
  reduce process/environment inspection and privilege escalation.

If the attacker becomes `root`, or compromises the FIM service user itself,
the host is already outside the protection boundary. Use host hardening,
EDR, egress controls, off-host ledger backups, and rapid secret rotation for
that case. Renaming or hiding a file does not solve a root-level compromise.

## Verification

```bash
```

The race detector requires a native Linux toolchain with CGO and GCC. The
official Windows functional demo is documented in `../SIDANG_WINDOWS.md`.
