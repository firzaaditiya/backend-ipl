# Fakta Konfigurasi Nyata (Ter-redaksi) — v1.5.0 Produksi

Dibaca langsung dari server produksi 5 November 2026, ~23:48 WIB
(hanya baca; TIDAK ADA nilai secret yang dicatat di sini — hanya nama
kunci dan panjang/keberadaan nilai).

## Sistem (GET /api/v1/system/info)

| Fakta | Nilai |
|---|---|
| Aplikasi | FIM-IPL |
| Versi | 1.5.0 (healthz; naskah v4 berhenti di v1.3.0) |
| Go | toolchain go1.27.3; `go.mod` minimum 1.26.0 (bukan 1.25.4 seperti di naskah Tabel 3.9) |
| OS / arsitektur | linux / amd64 |
| Interval scan | 120 dtk (produksi); default config 300 dtk |
| Worker | 4 |
| Watch path | `/var/www/html` |
| Mode karantina | `chmod_000` |
| Monitoring | aktif; maintenance mati |
| Terakhir restart | 2026-11-05T10:00:47Z (deploy v1.5.0); uptime ~6,8 jam saat dibaca |

## Struktur `config.json` produksi

Kunci yang ada (17 kunci): `admin_password`, `admin_username`,
`allowed_origins`, `auditor_password`, `auditor_username`,
`backup_webhook_url`, `cookie_secure`, `db_path`, `jwt_secret`,
`login_path`, `monitoring_enabled`, `scan_interval_sec`,
`server_port`, `telegram_chat_id`, `telegram_token`, `watch_paths`,
`worker_count`.

Keberadaan nilai (hanya panjang, bukan isi):

| Kunci | Status |
|---|---|
| `telegram_token` | TERISI (46 karakter) — **inilah temuan T-07** |
| `telegram_chat_id` | TERISI (11 karakter) — **temuan T-07** |
| `jwt_secret` | TERISI (64 karakter) |
| `admin_password` | KOSONG (berasal dari `fim.env`) |
| `auditor_password` | hash bcrypt (diizinkan sejak T-07; bukan plaintext) |

## Struktur `/etc/fim-ipl/fim.env` (root:root 0600)

Kunci yang ada (5 kunci): `FIM_JWT_SECRET`, `FIM_ADMIN_PASSWORD`,
`FIM_TELEGRAM_TOKEN`, `FIM_TELEGRAM_CHAT_ID`, `FIM_TRUST_PROXY`.

Keberadaan nilai (hanya ada/tidak, bukan isi):

| Kunci | Status |
|---|---|
| `FIM_JWT_SECRET` | TERISI (menang atas nilai di `config.json` lewat env override) |
| `FIM_ADMIN_PASSWORD` | TERISI |
| `FIM_TELEGRAM_TOKEN` | KOSONG (kunci ada, nilai kosong) |
| `FIM_TELEGRAM_CHAT_ID` | KOSONG (kunci ada, nilai kosong) |
| `FIM_TRUST_PROXY` | (nilai tidak diperiksa; flag aktif — terlihat dari perilaku CF-Connecting-IP) |

**Implikasi untuk T-07:** token + chat ID Telegram yang aktif saat ini
berasal SEMATA dari `config.json`. Langkah produksi T-07 adalah persis:
isi `FIM_TELEGRAM_TOKEN` + `FIM_TELEGRAM_CHAT_ID` di `fim.env` dengan
nilai dari `config.json`, kosongkan keduanya dari `config.json`, lalu
aktifkan `FIM_REQUIRE_EXTERNAL_SECRETS=1`.

## Unit systemd produksi (`systemctl cat fim-ipl`)

- `User=fim-ipl`, `Group=fim-ipl`, `WorkingDirectory=/opt/fim-ipl`,
  `ExecStart=/opt/fim-ipl/fim-ipl`, `Restart=on-failure`,
  `RestartSec=5`.
- `EnvironmentFile=-/etc/fim-ipl/fim.env`,
  `Environment=FIM_CONFIG_PATH=/opt/fim-ipl/data/config.json`,
  `FIM_STRICT_SECRETS=1`, `FIM_REQUIRE_LOCAL_API=1`,
  `FIM_SERVER_PORT=127.0.0.1:8080`.
- **TIDAK ADA** `FIM_REQUIRE_EXTERNAL_SECRETS` (target T-07),
  **TIDAK ADA** `MemoryMax` / `CPUWeight` / `Nice` /
  `IOSchedulingClass` (target T-08).
- `CapabilityBoundingSet=CAP_FOWNER` + `AmbientCapabilities=CAP_FOWNER`
  (base unit), `SupplementaryGroups=www-data`,
  `ReadWritePaths=/opt/fim-ipl/data` (base) + `/var/www/html`
  (override), `Environment=FIM_COOKIE_SECURE=1` (override),
  `NoNewPrivileges=true`, `PrivateTmp=true`,
  `ProtectSystem=strict`.

## Nginx (sites-enabled)

| Vhost | Listen | Server name | `/` → | `/api/` → |
|---|---|---|---|---|
| `fim-domain` | 80 | `fim.tpqalfawwaz.web.id` | 127.0.0.1:3001 (PM2) | 127.0.0.1:8080 (backend) |
| `fim-dashboard` | 3100 | `_` | 127.0.0.1:3001 | 127.0.0.1:8080 |
| `wordpress` | 80 (default) | `_` | WordPress (`/var/www/html`, PHP-FPM) | — |

**Koreksi untuk naskah:** Tabel 3.9 yang menulis "port 3100" untuk
backend adalah SALAH. Backend mendengarkan di `127.0.0.1:8080`;
port 3100 adalah vhost Nginx dasbor (bukan backend). Frontend PM2
mendengarkan di `127.0.0.1:3001` di belakang Nginx. Seluruh trafik
publik tiba di Nginx dari `127.0.0.1` lewat Cloudflare Tunnel.

## Respons `GET /settings` (v1.5.0, produksi)

Kunci yang dikembalikan (11 kunci): `allowed_origins`,
`auditor_configured`, `auditor_username`, `backup_webhook_url`,
`is_monitoring`, `maintenance_mode`, `scan_interval_sec`,
`telegram_chat_id`, `telegram_configured`, `watch_paths`,
`worker_count`. TIDAK ada `telegram_token` di respons (token tidak
pernah dikirim ke klien), dan belum ada `exclude_globs` atau flag
`*_from_env` — keduanya baru di v1.6.0 (T-05, T-07).
