# FIM-IPL Backend

**Versi: 1.6.0** (sumber versi tunggal: `AppVersion` di
`internal/api/handlers/system.go`; tampil di UI dan `/api/v1/healthz`).

FIM-IPL Backend adalah daemon File Integrity Monitoring (FIM) dan REST API
untuk memantau perubahan file pada server web. Sistem membandingkan hash
SHA-256 dengan baseline, mencatat kejadian ke Tamper-Evident Private Ledger lokal,
menonaktifkan file baru atau berubah (termasuk file sah, sampai diperiksa
operator), dan mengirim notifikasi operasional.

Repository ini berisi daemon + API, konfigurasi contoh, deployment unit
systemd, contoh secret, dan script simulasi serangan (`scripts/attack_sim.*`).
Yang SENGAJA tidak ada di repo ini: konfigurasi Nginx, PM2, dan Cloudflare
Tunnel untuk deployment produksi — lihat §Deployment untuk contoh blok proxy
yang dipakai di produksi dan batas tanggung jawab repo ini.

## Cara Kerja

```text
watch directory
      |
      v
filepath.Walk + worker pool + SHA-256
      |
      v
bandingkan dengan baseline
      |
      +--> CREATED / MODIFIED / MODE_CHANGED --> karantina --> ledger --> Telegram
      +--> DELETED ------------> ledger -----------------> Telegram
      +--> UNREADABLE ---------> karantina (fail-closed) --> ledger --> Telegram
      |
      v
metrics + SSE + dashboard API
```

Scanner menggunakan polling dengan `time.Ticker`, bukan filesystem event
watcher. Pendekatan ini dipilih agar perilaku deterministik, portabel di Linux
dan Windows, serta tidak kehilangan perubahan ketika daemon restart.

## Fitur

- Hash SHA-256 untuk baseline dan perubahan file.
- Worker pool untuk pemindaian paralel (hashing dan perbandingan baseline
  memakai `worker_count` yang sama, 1–16).
- Aksi `CREATED`, `MODIFIED`, `MODE_CHANGED` (perubahan izin saja, sejak
  v1.5.0), `QUARANTINE_BREACH` (karantina dibatalkan pemilik berkas, sejak
  v1.6.0), `DELETED`, dan `UNREADABLE`.
- Karantina Linux dengan `chmod 000`.
- Karantina Windows dengan best-effort ReadOnly attribute.
- Tamper-Evident Private Ledger lokal berbasis Bbolt dan hash-chain.
  "Tamper-Evident" di sini berarti append-only + hash-chain di tingkat
  aplikasi pada satu node: perubahan retroaktif pada entri yang sudah
  di-anchor dapat TERDETEKSI saat verifikasi, BUKAN mustahil dilakukan —
  root dapat menulis ulang file Bbolt dan menghitung ulang rantai. Karena
  itu backup off-host dan anchoring eksternal wajib dipakai (lihat §Batasan).
- Verifikasi hash-chain lokal; head hash diekspor untuk perbandingan manual
  off-box (tidak ada verifikasi otomatis terhadap salinan eksternal).
- Export dan backup ledger ke Telegram/webhook.
- Retry Telegram untuk pengiriman pesan teks (maks. 3x, backoff 1–10 detik,
  menghormati `retry_after` 429); pengiriman dokumen backup tidak di-retry;
  tidak ada outbox persisten.
- JWT HS256, bcrypt, RBAC Super Admin/Auditor, rate limit, CORS, security
  headers, validasi webhook, dan SSE untuk pembaruan dashboard real-time
  setelah deteksi polling.
- Environment override untuk secret deployment (JWT, password admin/auditor,
  token Telegram) dan sebagian parameter operasi — lihat tabel di
  §Konfigurasi dan Secret untuk daftar persisnya. `watch_paths` dan
  `login_path` hanya lewat `config.json`/Settings API; `allowed_origins`
  TIDAK bisa diubah dari dashboard — hanya lewat `config.json` atau
  `FIM_ALLOWED_ORIGINS`.
- Mode strict (`FIM_STRICT_SECRETS=1`) yang menolak JWT secret lemah saat
  startup. Yang menolak penyimpanan kredensial di `config.json` adalah flag
  terpisah, `FIM_REQUIRE_EXTERNAL_SECRETS=1` — keduanya tidak sama.

## Persyaratan

- Go 1.26.0 atau lebih baru (direktif `go.mod`; toolchain produksi
  terverifikasi 1.27.3).
- Linux direkomendasikan untuk deployment produksi.
- Windows didukung untuk pengembangan dan simulasi fungsional.
- `curl` untuk health check.
- Telegram Bot API hanya diperlukan jika notifikasi Telegram dipakai.

Dependensi kunci (terkunci di `go.sum`): `golang-jwt/jwt/v5 v5.3.1`,
`go.etcd.io/bbolt v1.4.3`, `golang.org/x/crypto v0.58.0`,
`golang.org/x/sys v0.49.0` (require langsung sejak v1.5.0, dipakai paket
`internal/fsx`). v1.4.0 menaikkan `x/crypto` dari v0.51.0 ke v0.58.0 dan
`x/sys` v0.44.0 ke v0.49.0 setelah `govulncheck` menemukan 17 vuln yang
tidak terpanggil di `x/crypto` v0.51.0; setelah kenaikan tersisa 1 vuln
yang tidak terpanggil (perbaikannya hanya ada di versi pseudo-release,
bukan rilis stabil, jadi tidak dikejar). Hasil `govulncheck` v1.5.0 sama
(2026-11-05, lihat §Testing dan Quality Gate).

## Menjalankan Lokal

Salin konfigurasi contoh. File hasil salinan bersifat lokal dan tidak boleh
dimasukkan Git:

```bash
cp data/config.example.json data/config.json
export FIM_CONFIG_PATH="$PWD/data/config.json"
export FIM_JWT_SECRET="buat-rahasia-acak-minimal-32-karakter"
export FIM_ADMIN_PASSWORD="buat-password-admin-kuat"
# Dev HTTP lokal: cookie Secure tidak berlaku tanpa HTTPS, dan API hanya
# mengikat localhost (bukan semua interface).
export FIM_COOKIE_SECURE=0
export FIM_SERVER_PORT=127.0.0.1:8080
go run ./cmd/server
```

Health check:

```bash
curl http://127.0.0.1:8080/api/v1/healthz
```

Windows PowerShell:

```powershell
Copy-Item data/config.example.json data/config.json
$env:FIM_CONFIG_PATH = (Resolve-Path data/config.json).Path
$env:FIM_JWT_SECRET = 'buat-rahasia-acak-minimal-32-karakter'
$env:FIM_ADMIN_PASSWORD = 'buat-password-admin-kuat'
$env:FIM_COOKIE_SECURE = '0'
$env:FIM_SERVER_PORT = '127.0.0.1:8080'
go run ./cmd/server
```

Jangan menjalankan daemon sebagai user web pada deployment produksi.

## Setup awal (akun admin pertama)

Bila `FIM_ADMIN_PASSWORD` tidak di-set, daemon boot dengan admin kosong.
Satu-satunya cara membuat akun Super Admin pertama adalah endpoint publik
`POST /api/v1/setup` (sekali saja; setelah admin ada, endpoint ini
mengembalikan 403 `password already configured`):

```bash
curl -X POST http://127.0.0.1:8080/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"GANTI-DENGAN-PASSWORD-KUAT-8-SAMPAI-72-KARAKTER"}'
```

Username wajib diisi dan password harus 8–72 karakter (di luar itu 400);
hal yang sama berlaku untuk `POST /api/v1/setup/auditor`. Bila penyimpanan
konfigurasi gagal setelah validasi, perubahan di memori dibatalkan agar
memori dan disk tidak berbeda (sejak v1.5.0).

Setelah itu: login di `POST /api/v1/secure-gate`, lalu `POST
/api/v1/baseline/init` dan `POST /api/v1/monitoring/start` (keduanya Super
Admin). Mengganti password admin/auditor membatalkan semua sesi aktif —
token lama ditolak walau belum kedaluwarsa (lihat §Sesi dan autentikasi).

## Konfigurasi dan Secret

Konfigurasi non-rahasia dapat disimpan di `config.json`. Secret deployment
sebaiknya hanya diberikan lewat environment atau systemd credentials.

| Variable | Kegunaan |
| --- | --- |
| `FIM_CONFIG_PATH` | Lokasi file konfigurasi |
| `FIM_SERVER_PORT` | Alamat dan port API |
| `FIM_DB_PATH` | Lokasi database Bbolt |
| `FIM_JWT_SECRET` | Secret signing JWT, minimal 32 karakter |
| `FIM_ADMIN_USERNAME` | Override username Super Admin |
| `FIM_ADMIN_PASSWORD` | Override password Super Admin |
| `FIM_AUDITOR_USERNAME` | Override username Auditor |
| `FIM_AUDITOR_PASSWORD` | Override password Auditor |
| `FIM_TELEGRAM_TOKEN` | Token bot Telegram |
| `FIM_TELEGRAM_CHAT_ID` | Tujuan chat Telegram |
| `FIM_BACKUP_WEBHOOK_URL` | URL webhook backup ledger (harus alamat publik) |
| `FIM_WEBHOOK_SECRET` | Secret HMAC-SHA256 untuk menandatangani POST webhook backup (sejak v1.5.0; bila tidak di-set, webhook dikirim tanpa tanda tangan) |
| `FIM_SCAN_INTERVAL_SEC` | Interval scan, 30–86400 (nilai di luar rentang diabaikan) |
| `FIM_WORKER_COUNT` | Worker hashing/perbandingan, 1–16 |
| `FIM_ALLOWED_ORIGINS` | Daftar origin CORS dipisahkan koma |
| `FIM_COOKIE_SECURE` | `1` (default) = cookie sesi memakai atribut Secure; `0` hanya untuk dev HTTP lokal |
| `FIM_TRUST_PROXY` | `1` = rate limit, pembatas SSE, dan log login memakai IP klien dari header proxy. Hanya aktifkan bila backend hanya terjangkau lewat reverse proxy tepercaya yang MENIMPA `X-Forwarded-For` dengan IP penghubung (`proxy_set_header X-Forwarded-For $remote_addr`). Backend memakai `CF-Connecting-IP` dulu (ditulis ulang edge Cloudflare menjadi IP klien asli, tidak dapat dipalsukan lewat Tunnel), lalu `X-Forwarded-For`, lalu `X-Real-IP`. Tanpa flag ini, semua request lewat proxy terlihat dari `127.0.0.1` dan berbagi satu bucket rate limit. |
| `FIM_STRICT_SECRETS` | `1` = tolak JWT secret lemah |
| `FIM_REQUIRE_EXTERNAL_SECRETS` | `1` = tolak credential di `config.json` |
| `FIM_REQUIRE_LOCAL_API` | `1` = tolak binding API wildcard |

`FIM_REQUIRE_EXTERNAL_SECRETS=1` dan `FIM_REQUIRE_LOCAL_API=1` sebaiknya selalu
dipakai di server produksi, DENGAN satu pengecualian: `FIM_REQUIRE_EXTERNAL_SECRETS=1`
tidak kompatibel dengan penyimpanan Telegram/Auditor lewat Settings API (API itu
memang menulis ke `config.json`). Deployment yang memakai Settings API harus
mematikan flag tersebut dan menerima `config.json` (0600, milik `fim-ipl`)
sebagai sumber kebenaran runtime untuk Telegram dan Auditor, sementara JWT
secret dan password admin tetap dari `fim.env` (environment menang atas
`config.json` saat restart).

## Sesi dan autentikasi (v1.1.0, diperketat v1.4.0, pencabutan per-sesi v1.5.0)

Satu-satunya mekanisme autentikasi adalah cookie sesi HttpOnly:

- Login (`POST /api/v1/secure-gate`) TIDAK mengembalikan token di body JSON.
  Server menulis cookie `fim_session` (`Path=/api/v1`, `HttpOnly`,
  `SameSite=Lax`, `Secure` bila `FIM_COOKIE_SECURE=1`) berisi JWT HS256
  24 jam dengan klaim role. JavaScript tidak bisa membaca cookie ini,
  sehingga token tidak bisa dicuri lewat XSS.
- Header `Authorization: Bearer` TIDAK lagi diterima (sengaja, agar tidak ada
  dua jalur autentikasi). Frontend membuktikan sesi lewat `GET /api/v1/auth/me`
  pada setiap refresh halaman, dan keluar lewat `POST /api/v1/auth/logout`
  yang menghapus cookie.
- Sejak v1.5.0 setiap token membawa ID sesi acak (`jti`) dan logout
  MENCABUT sesi itu di sisi server: `jti` ditulis ke bucket `revoked_tokens`
  di Bbolt dan token yang sama ditolak pada request berikutnya. Token yang
  diterbitkan sebelum v1.5.0 (tanpa `jti`) tidak dapat dicabut satu per satu;
  yang tetap membatalkan SEMUA token adalah pergantian kredensial:
  `POST /api/v1/setup` dan `POST /api/v1/setup/auditor` menaikkan
  `session_epoch` di `config.json`, dan token dari epoch lama ditolak.
- Percobaan login yang gagal dan yang berhasil dicatat di log server
  (username + IP klien, tanpa password; username dipotong 64 karakter agar
  satu baris log tidak membengkak). Username dibandingkan dalam waktu
  konstan dan username tak dikenal tetap menjalani bcrypt dummy agar timing
  seragam.
- CSRF: selain `SameSite=Lax`, request mutasi (`POST`/`PUT`/`DELETE`/`PATCH`)
  diperiksa Origin-nya — lolos bila Origin kosong (curl/alat admin), sama
  dengan Host request (same-origin lewat proxy), atau ada di allowlist.
  Bila allowlist kosong, HANYA same-origin yang lolos (fail-closed sejak
  v1.4.0; sebelumnya pemeriksaan nonaktif bila allowlist kosong). CORS pun
  fail-closed: tanpa allowlist, server tidak mengirim header
  `Access-Control-Allow-Origin` sama sekali. Produksi wajib mengisi
  `allowed_origins` dengan origin dashboard.
- Rate limit: 60 request/menit per-IP (burst 60) untuk semua endpoint
  kecuali SSE `/events`, termasuk preflight OPTIONS sejak v1.5.0 (sebelumnya
  OPTIONS lolos sebelum limiter); endpoint login dan setup awal memakai
  limiter terpisah yang lebih ketat, 10 request/menit per-IP (keduanya
  mengembalikan 429 dengan `Retry-After: 60`). Rate limit memakai IP klien
  dengan urutan `CF-Connecting-IP`, lalu `X-Forwarded-For`, lalu
  `X-Real-IP` — dan hanya bila `FIM_TRUST_PROXY=1` (lihat tabel env).
- Frontend dan API WAJIB satu origin di deployment produksi (proxy Nginx
  yang sama). Kode tetap mengizinkan origin lintas situs yang terdaftar di
  `allowed_origins`; satu origin adalah pilihan deployment, bukan paksaan
  kode.

## Status monitoring antar restart

Status monitoring dipertahankan di `config.json` (`monitoring_enabled`) oleh
endpoint Start/Stop, dan daemon melanjutkannya otomatis saat boot bila
baseline tidak kosong. Restart proses (systemctl restart, reboot) TIDAK
menghapus flag ini — hanya tombol Stop di dashboard yang boleh mematikannya.
Maintenance mode sengaja TIDAK dipertahankan: restart mengakhirinya agar
perlindungan kembali aktif (fail-safe).

## Karantina: permission asli dikembalikan

Saat karantina berhasil, permission asli file dicatat di ledger (bucket
terpisah, bukan bagian hash-chain). Release mengembalikan permission persis
itu; bila catatan tidak ada (file dikarantina sebelum v1.1.0), dipakai
fallback 0644 dan respons menandainya (`restored_original=false`).

## Verifikasi karantina (v1.2.0)

Sejak v1.2.0, `quarantine.Apply` dan `quarantine.Release` tidak lagi
dinyatakan berhasil hanya karena `chmod` tidak mengembalikan galat. Setelah
chmod diterapkan, izin berkas dibaca kembali dan dibandingkan dengan izin
target (000 untuk karantina, izin asli atau 0644 untuk pelepasan). Bila
verifikasi gagal, operasi dilaporkan gagal, sehingga karantina yang
diabaikan sistem berkas tidak pernah dilaporkan berhasil secara diam-diam.
Windows dikecualikan dari verifikasi mode karena semantik izinnya berbeda.

Dasbor versi 1.2.0 juga menampilkan hitung mundur pemindaian berikutnya,
yang dihitung dari siklus terakhir yang tercatat pada metrik ditambah
interval yang dikonfigurasi. Hitung mundur ini bernilai kosong (bukan
tebakan) bila pemantauan berhenti, mode pemeliharaan aktif, atau belum ada
siklus yang tercatat.

## Daftar karantina saat ini (v1.3.0)

Sejak v1.3.0, endpoint baca `GET /api/v1/quarantine/list` mengembalikan
berkas yang status TERAKHIR-nya masih dikarantina, beserta izin asli yang
akan dipulihkan dan izin berkas saat ini di disk. Sebelumnya operator
harus memburu blok terakhir di Audit Trail untuk mengetahui apa saja yang
sedang diisolasi; sekarang dasbor menampilkan daftar itu langsung, dan
pelepasan dapat dilakukan dari dasbor maupun dari Audit Trail. Respons
pelepasan kini juga memuat `restored_mode` sebagai field terpisah, agar
antarmuka tidak lagi menampilkan angka izin yang ditebak (sebelumnya
pesan sukses di Audit Trail selalu menulis 0644, padahal izin yang
dipulihkan bisa 0600 atau 0640).

## Deteksi perubahan izin (MODE_CHANGED) (v1.5.0)

Sebelum v1.5.0, scanner hanya membandingkan hash SHA-256: perubahan izin
saja (mis. `chmod 777 wp-config.php`) tidak menghasilkan kejadian apa pun —
hanya `chmod 000` yang tertangkap secara tidak langsung sebagai UNREADABLE.
Sejak v1.5.0, setiap entri baseline juga menyimpan mode izin, dan setiap
siklus membandingkan hash DAN mode:

- Hash berbeda → `MODIFIED` (dengan mode lama dan baru).
- Hash sama, mode berbeda → `MODE_CHANGED`, dengan `old_hash == new_hash`
  dan metadata `old_mode`/`new_mode` pada blok. Seperti `quarantine_err`,
  kedua mode itu metadata dan TIDAK masuk material hash blok, jadi formula
  hash tidak berubah dan ledger lama tetap terverifikasi.
- `MODE_CHANGED` dikarantina seperti `MODIFIED`: berkas dinonaktifkan
  sampai operator memeriksa dan melepasnya. Perlu dipahami arti pelepasan
  di sini: pelepasan mengembalikan izin seperti SAAT DIKARANTINA — untuk
  berkas `MODE_CHANGED` berarti izin BARU (mis. 0777), bukan izin baseline
  lama (0644). Pelepasan adalah persetujuan operator atas keadaan berkas
  saat itu; perubahan izinnya sendiri tetap tercatat permanen di blok
  `MODE_CHANGED` (mode lama → mode baru). Bila operator ingin berkas
  kembali ke izin baseline, ubah izinnya secara manual lalu jalankan
  `baseline/update` (atau lewat maintenance mode, lihat SOP di naskah).

Baseline yang dibuat sebelum v1.5.0 tidak punya mode tersimpan. Pada siklus
pertama setelah upgrade, mode setiap berkas diadopsi diam-diam ke baseline
(TANPA kejadian anomali) — bila tidak begitu, seluruh 3901 berkas akan
dilaporkan `MODE_CHANGED` sekaligus. Adopsi ini dicatat di log server
("Adopted modes for N baseline file(s)").

## Verifikasi karantina per siklus (QUARANTINE_BREACH) (v1.6.0)

`MODE_CHANGED` saja tidak menutup satu celah: setelah karantina berhasil,
baseline menyimpan hash dan mode hasil scan SEBELUM `chmod 000`. Bila
pemilik berkas (mis. `www-data`) mengembalikan izin ke mode aslinya,
hash dan mode sama persis dengan baseline — perbandingan biasa tidak
memicu kejadian apa pun, sementara ledger tetap menyatakan berkas
terkarantina. Celah ini terbukti lewat reproduksi (T-01): berkas yang
dikarantina dikembalikan ke 0644 dan dua siklus berikutnya mencatat
"No anomalies detected", padahal berkas sudah bisa dipakai lagi.

Sejak v1.6.0, setiap siklus memeriksa ulang semua path yang tercatat
dikarantina (daftar dari `GetCurrentlyQuarantinedPaths`) dengan `Lstat`
— tanpa hashing ulang:

- Berkas yang izinnya tidak lagi berlaku (dapat dibaca atau dijalankan
  lagi) dicatat sebagai blok `QUARANTINE_BREACH` dengan `old_hash ==
  new_hash` (isi tidak berubah), `old_mode` 000, dan `new_mode` izin
  yang ditemukan di disk; lalu dikarantina ulang (`chmod 000`) dan
  dikirim alert Telegram berlabel URGENT.
- Berkas yang hanya bisa ditulis (mis. 0200) tetap dianggap karantina
  berlaku, karena tidak dapat dibaca maupun dijalankan; begitu izinnya
  dipulihkan penuh, `MODIFIED` atau breach akan menangkapnya.
- Bila perbandingan sudah menghasilkan event untuk path itu (mis.
  `MODIFIED` karena isi ikut berubah), event itulah yang diproses —
  tidak ada blok ganda untuk satu kejadian. Berkas yang hilang dilewati
  (`DELETED` sudah ditangani perbandingan).
- Baseline TIDAK diubah oleh breach: baseline sudah menyimpan hash dan
  mode yang benar. Satu pemilik yang mengembalikan izin setiap siklus
  menghasilkan satu blok breach per siklus — itu disengaja: setiap
  pembatalan adalah kejadian tersendiri yang harus terlihat.

Batas yang tetap berlaku: pemilik berkas selalu bisa mengembalikan izin,
jadi selalu ada jendela sampai satu interval scan sebelum breach
terdeteksi dan karantina diterapkan ulang. Yang diperbaiki adalah
keheningan: breach kini tercatat, terlihat, dan dikarantina ulang.

## Formula hash blok v2 (hash_version) (v1.6.0)

Formula hash v1 (v1.0–v1.5.0) hanya melindungi
`ID|Timestamp|FilePath|Action|OldHash|NewHash|PrevBlockHash|Quarantined`,
dengan pemisah `|` yang tidak di-escape. Dua celah: (1) `OldMode`,
`NewMode`, dan `QuarantineErr` tidak masuk material hash — pada
`MODE_CHANGED`, `OldHash == NewHash`, jadi perubahan izin itu sendiri
tidak terlindungi sama sekali; (2) path yang mengandung `|` bisa
dipalsukan menjadi field lain.

Sejak v1.6.0, setiap blok baru memakai formula v2 (`hash_version: 2`):

- Material hash mencakup SELURUH field kejadian: ID, Timestamp,
  FilePath, Action, OldHash, NewHash, OldMode, NewMode, Quarantined,
  QuarantineErr, Actor, Detail, PrevBlockHash, dan HashVersion sendiri.
- Encoding-nya length-prefixed (`panjang:nilai` per field, urutan
  tetap), sehingga batas field tidak pernah ambigu.
- `VerifyChain` memilih formula per blok dari `hash_version`-nya.
  Blok lama tanpa field itu (v1) diverifikasi dengan formula lama yang
  tidak berubah — 29 blok produksi v1.5.0 tetap valid tanpa migrasi.
  Versi formula yang tidak dikenal ditolak (rantai gagal di blok itu),
  bukan diam-diam diverifikasi dengan formula lama.

Catatan untuk T-03: field `Actor` dan `Detail` sudah masuk material
hash v2 sejak sekarang (kosong untuk temuan pemindaian), sehingga saat
T-03 mulai mengisinya untuk aksi administratif, formula tidak perlu
berubah lagi.

## Formula hash blok v3 dan digest baseline (v1.6.0, T-04)

Sejak v1.6.0, blok baru memakai formula v3 (`hash_version: 3`): v2
ditambah `BaselineDigest` dan `BaselineCount`. Setiap versi formula
tidak pernah diubah setelah didefinisikan — kebutuhan baru memakai versi
baru, sehingga blok v1 dan v2 yang sudah ada tetap terverifikasi dengan
formula lamanya (rantai campuran v1→v2→v3 terverifikasi di instance uji).

Baseline hidup di bucket Bbolt yang tidak masuk hash-chain, sehingga
root yang mengedit satu entri baseline secara langsung tidak merusak
rantai. Digest menutup celah itu:

- Setiap blok `BASELINE_INIT`/`BASELINE_UPDATE` membawa SHA-256 atas
  seluruh isi baseline pada saat itu, dalam format kanonis satu baris
  per berkas `path|hash|mode|size` (mode dan size desimal, diurutkan
  berdasarkan path), beserta jumlah berkasnya. Digest ikut dihitung ke
  dalam hash blok v3.
- `GET /api/v1/ledger/verify-baseline` (read-only, Auditor boleh)
  membandingkan digest blok baseline terakhir dengan digest baseline
  saat ini. Ketidakcocokan berarti ada entri yang berubah di luar jalur
  resmi. Verifikasi ini melengkapi `VerifyChain` — rantai yang valid
  tidak menjamin baseline tidak diubah, dan sebaliknya.
- Mode pemulihan karantina (`GetQuarantineMode`) kini bersumber dari
  RANTAI — mode pada blok karantina terakhir untuk path itu — bukan
  hanya dari bucket `quarantine_modes` yang mutable. Bucket hanya
  dipakai sebagai fallback untuk karantina lama yang bloknya tidak
  membawa mode. Unit test membuktikan manipulasi langsung pada bucket
  tidak lagi mengubah mode yang dipulihkan.

## Aksi administratif di ledger (v1.6.0)

Sejak v1.6.0, setiap endpoint mutasi mencatat satu blok audit ke ledger
selain menjalankan aksinya (pola yang sama seperti `RELEASED`):

| Endpoint | Aksi | Detail |
|---|---|---|
| `POST /baseline/init` | `BASELINE_INIT` | `baseline dibuat: N berkas` |
| `POST /baseline/update` | `BASELINE_UPDATE` | alasan wajib dari operator |
| `POST /monitoring/start` | `MONITORING_START` | `interval X detik, Y worker` |
| `POST /monitoring/stop` | `MONITORING_STOP` | — |
| `POST /maintenance/enable` | `MAINTENANCE_ON` | — |
| `POST /maintenance/disable` | `MAINTENANCE_OFF` | — |
| `POST /settings` | `SETTINGS_CHANGED` | nama field yang diubah SAJA (tidak pernah nilainya) |
| `POST /setup/auditor` | `AUDITOR_SET` | `auditor: <username>` |
| `POST /quarantine/release` | `RELEASED` | alasan wajib dari operator |

- **Actor** diisi `username (Peran) dari IP`, dibaca dari klaim JWT di
  awal handler — sebelum mutasi — karena mengatur auditor menaikkan
  epoch sesi dan membuat token pemanggil tidak valid lagi.
- **Alasan wajib** (1–500 karakter) berlaku untuk pelepasan karantina
  dan baseline/update; tanpa alasan, endpoint menolak 400. Alasan
  tersimpan permanen di ledger.
- Blok aksi administratif memakai `file_path` penanda `"[admin]"` karena
  tidak ada berkas yang terlibat; mudah dicari di Audit Trail.
- **Perubahan definisi "Anomalies" (penting untuk naskah):** sejak
  v1.6.0, `total_anomalies` di `GET /dashboard/stats` hanya menghitung
  temuan pemindaian (`CREATED`, `MODIFIED`, `MODE_CHANGED`,
  `QUARANTINE_BREACH`, `DELETED`, `UNREADABLE`). Blok `RELEASED` dan
  aksi administratif TIDAK dihitung. Angka historis v1.0–v1.5.0 tidak
  berubah (belum ada blok admin saat itu), tetapi angka setelah v1.6.0
  tidak lagi bisa dibandingkan mentah dengan angka lama tanpa catatan
  ini. Respons mutasi membawa `"audited": true/false` (false bila
  pencatatan ke ledger gagal; aksinya sendiri tetap berjalan).
- Auditor yang ditolak 403 oleh router tidak pernah mencapai handler,
  sehingga tidak menghasilkan blok apa pun.

## Aturan pengecualian dan kebijakan uploads (v1.6.0, T-05)

Tanpa pengecualian, sistem dapat merusak situsnya sendiri: setiap berkas
baru yang sah — cache plugin, staging update WordPress, gambar yang
diunggah — terdeteksi CREATED lalu dikarantina chmod 000. Dua lapis
aturan mencegahnya:

1. **`exclude_globs`** (konfigurasi, diubah lewat Settings API):
   pola path yang dikecualikan SELURUHNYA dari deteksi. Default
   `wp-content/cache/**` dan `wp-content/upgrade/**`. Pola memakai
   `**` untuk subdirektori apa pun; pola tidak valid ditolak 400.
   Perubahan tercatat di ledger sebagai `SETTINGS_CHANGED` (hanya nama
   field). Daftar kosong eksplisit berarti tidak ada pengecualian glob.
2. **Kebijakan uploads** (bawaan, tidak dapat dimatikan): berkas
   NON-KODE di bawah `wp-content/uploads/**` dikecualikan — gambar,
   dokumen, media yang diunggah lewat WordPress. Berkas yang menyerupai
   kode (`.php`, `.php.*`, `.phtml`, `.phar`, `.htaccess`, `.user.ini`,
   dan sejenisnya — lihat `isCodeLike`) TETAP dipantau dan dikarantina,
   karena uploads adalah jalur klasik webshell.

Pengecualian bukan blind spot diam-diam:

- Berkas yang dikecualikan TETAP masuk baseline (ditulis tanpa event
  saat siklus menemukannya) — jadi terlacak dan tercakup digest baseline
  (T-04). Menghapus pengecualian kemudian tidak menimbulkan banjir
  CREATED palsu.
- Jumlah berkas yang dikecualikan per siklus dicatat di metrik
  (`excluded_files`), ditampilkan di dasbor (baris "Siklus terakhir")
  dan di `GET /dashboard/stats`.
- Setelah perubahan sah (unggahan, update plugin), baseline berubah di
  luar rebuild — `verify-baseline` akan melaporkan mismatch sampai
  operator melakukan maintenance + rebuild baseline (SOP yang sama
  seperti perubahan sah lainnya).

Bukti produksi (5 Nov 2026): seluruh 29 blok ledger produksi diperiksa
— 7 blok CREATED, SEMUANYA dari simulasi (`fim-sim-*.php`), **0 blok
CREATED di luar simulasi**. Artinya, sampai v1.5.0, situs belum pernah
mengalami "self-DoS" nyata; pengecualian ini adalah pencegahan, bukan
perbaikan atas insiden.

## Manajemen secret (v1.6.0, T-07)

Kredensial deployment dikelola lewat environment (`/etc/fim-ipl/fim.env`,
root:root 0600), bukan lewat `config.json`:

- **JWT secret, password admin, token + chat ID Telegram**: dari fim.env.
  `FIM_REQUIRE_EXTERNAL_SECRETS=1` membuat boot GAGAL bila ada kredensial
  plaintext di config.json (pemeriksaan sadar sumber — nilai dari env
  diizinkan). Settings API dan UI menolak perubahan Telegram bila
  sumbernya env (kolom dinonaktifkan, pesan menjelaskan harus mengubah
  fim.env + restart).
- **Hash bcrypt auditor di config.json DIIZINKAN** (pengecualian): auditor
  dibuat saat runtime lewat API SetupAuditor, dan user daemon (fim-ipl)
  tidak bisa menulis fim.env yang root:root 0600 — memindahkan auditor ke
  env akan merusak alur setup. Hash bukan kredensial yang bisa dipakai
  (tidak bisa ditempel ke form login); brute-force offline ditahan biaya
  bcrypt. Password auditor plaintext tetap ditolak.
- **Bug Load yang diperbaiki (T-07)**: boot pertama tanpa config.json
  selalu menulis secret JWT acak ke disk walau env sudah menyediakan
  `FIM_JWT_SECRET`. Sekarang file config tidak dibuat bila env menyediakan
  secret-nya; tanpa env, secret acak tetap dibuat dan disimpan agar sesi
  stabil melewati restart.
- **Rotasi** (dilakukan operator, BUKAN oleh kode): token Telegram yang
  pernah ditempel di chat, password admin/auditor, dan JWT secret harus
  dirotasi — token lewat BotFather, password lewat Settings API / fim.env,
  JWT secret lewat fim.env (semua sesi lama batal).

### Unit systemd repo vs produksi (T-07)

Unit di repo (`deploy/fim-ipl.service`) adalah template lengkap. Unit
produksi (`/etc/systemd/system/fim-ipl.service`) sama secara efektif,
tetapi dibagi dua file (sejarah: CAP_FOWNER ditemukan belakangan):

| | Repo (template) | Produksi |
|---|---|---|
| `FIM_REQUIRE_EXTERNAL_SECRETS` | `=1` | BELUM ADA — diaktifkan saat langkah produksi T-07 (Telegram pindah ke fim.env; butuh persetujuan eksplisit sebelum deploy) |
| `FIM_COOKIE_SECURE` | `=1` (di unit) | `=1` (di `override.conf`) |
| `CAP_FOWNER` (bounding + ambient) | di unit | di `override.conf` |
| `SupplementaryGroups=www-data` | di unit | di `override.conf` |
| `ReadWritePaths` | `/opt/fim-ipl/data /var/www/html` (satu baris) | `/opt/fim-ipl/data` (unit) + `/var/www/html` (override) |
| `fim.env` | contoh di `deploy/fim-ipl.env.example` | `FIM_JWT_SECRET, FIM_ADMIN_PASSWORD, FIM_TELEGRAM_TOKEN, FIM_TELEGRAM_CHAT_ID, FIM_TRUST_PROXY` |

Bila suatu saat unit produksi ditulis ulang dari template, drop-in
`override.conf` tidak lagi diperlukan (isinya sudah ada di template) —
tetapi JANGAN menghapus drop-in sebelum memverifikasi `systemctl cat
fim-ipl` menunjukkan nilai yang sama.

## Jangkar eksternal dan verifikasi terjadwal (v1.6.0, T-06)

Ledger di satu node punya batas yang tidak bisa dihapus oleh kriptografi
apa pun: **verifikasi lokal tidak dapat mendeteksi pemotongan ekor**
(tail truncation). Menghapus blok-blok terakhir menghasilkan rantai yang
lebih pendek tetapi tetap utuh — hash-chain hanya membuktikan tidak ada
yang diubah DI DALAM rantai yang tersisa, bukan bahwa tidak ada yang
dihapus. Yang mendeteksinya adalah **jangkar eksternal**: salinan head
hash di luar server. Karena itu:

- **Setiap alert Telegram membawa jangkar.** Alert per-blok (≤3 anomali
  per siklus) mencantumkan `Block hash` LENGKAP (64 heksa). Ringkasan
  batch dan peringatan massal mencantumkan ID + hash pendek tiap blok
  serta `Block terakhir` + `Hash rantai` lengkap. Caption backup ledger
  mencantumkan `Block terakhir` + `Head hash`. Bila head hash di Telegram
  tidak sama dengan head hash rantai saat ini, ada blok yang hilang —
  walau verifikasi lokal melaporkan "chain intact".
- **Verifikasi terjadwal.** Daemon memeriksa rantai + digest baseline
  1 menit setelah boot, lalu setiap jam, dan mencatat hasilnya (bertahan
  melewati restart). Dasbor menampilkan "Terakhir diverifikasi" (waktu,
  status rantai, head block). Rantai yang RUSAK memicu alert Telegram
  URGENT (`RANTAI LEDGER RUSAK`). Ketidakcocokan digest baseline TIDAK
  dialert — perubahan sah (unggahan, update plugin) memang membuat digest
  usang sampai rebuild; alert untuk itu hanya akan melatih operator
  mengabaikan alert. Status ketidakcocokan tetap terlihat di dasbor.
- **Verifier mandiri `cmd/verify`.** `fim-verify <export.json>`
  menghitung ulang rantai dari file ekspor JSON tanpa membuka database,
  memakai logika yang persis sama dengan server (formula v1/v2/v3).
  Kode keluar 0 = utuh, 1 = rusak, 2 = pemakaian/file salah. Cocok untuk
  audit di mesin lain atau di luar server.
- **HMAC blok TIDAK ditambahkan** (sengaja): kunci yang disimpan di
  server yang sama tidak menghentikan penyerang dengan akses root — yang
  lebih bernilai adalah jangkar eksternal per kejadian di atas.

Perbaikan yang ditemukan saat menguji T-06 (bug T-04 yang ikut
diperbaiki di sini): `scanAndSaveBaseline` tidak mencatat `Mode` berkas,
sehingga setiap rebuild menulis Mode 0 untuk semua berkas; siklus
berikutnya mengadopsi mode diam-diam dan digest berubah tepat setelah
rebuild — verify-baseline selalu mismatch sampai rebuild berikutnya.
Sejak perbaikan ini, rebuild mencatat mode dan digest stabil melewati
siklus (diuji: rebuild → match=true, satu siklus kemudian tetap
match=true).

## Backup & notifikasi

- Backup ledger (export JSON) berjalan otomatis setiap 24 jam dan saat
  anomali kritis: ≥5 blok baru dalam satu siklus (label `critical-anomaly`).
  Backup manual lewat `POST /api/v1/backup/run` gagal hanya bila Telegram
  DAN webhook sama-sama gagal; satu kanal yang berhasil sudah cukup.
- Peringatan Telegram: ≤3 anomali dikirim per blok; >3 anomali dalam satu
  siklus diringkas menjadi satu pesan; ≥50 anomali menjadi satu pesan
  perubahan massal (maks. 5 berkas disebut). Sejak v1.5.0 pengiriman
  berjalan asinkron lewat antrean pekerja, sehingga Telegram yang lambat
  tidak pernah menunda siklus scan berikutnya (sebelumnya pengiriman
  sinkron dapat membuat satu siklus melebihi interval 120 detik dan siklus
  berikutnya dilewati sebagai "overlap").
- Sejak v1.6.0 pesan Telegram memakai format HTML minimal (judul tebal,
  nilai dalam monospace, emoji hanya di judul); semua nilai dinamis
  di-escape, dan bila Telegram menolak formatnya pesan dikirim ulang
  sebagai teks biasa.
- Anomali yang belum selesai TIDAK ditulis ulang ke ledger setiap siklus;
  ledger hanya mencatat kejadian baru. Setelah karantina berhasil, hash
  baru berkas masuk ke baseline, sehingga berkas yang sama berhenti
  dilaporkan pada siklus berikutnya.
- Webhook backup mengirim header `X-FIM-IPL-File` (nama file export) dan,
  bila `FIM_WEBHOOK_SECRET` di-set, `X-FIM-IPL-Signature`
  (`sha256=<HMAC-SHA256(secret, timestamp + "." + body)>`) beserta
  `X-FIM-IPL-Timestamp`. Penerima sebaiknya menolak timestamp yang lebih
  tua dari 5 menit (anti-replay). Tanpa secret, webhook dikirim tanpa tanda
  tangan (lihat §Batasan).
- Koneksi webhook memakai dialer yang hanya menghubungi alamat IP publik
  yang sudah divalidasi: hostname di-resolve SEKALI, lalu dial memakai
  literal IP hasil resolve itu — tidak ada lagi resolve kedua yang membuka
  jendela DNS rebinding (sebelumnya ada di v1.4.0). TLS tetap memverifikasi
  sertifikat terhadap hostname URL.

## Pengerasan v1.5.0

- Deteksi perubahan mode (`MODE_CHANGED`) seperti dijelaskan di atas,
  termasuk adopsi mode baseline lama tanpa kejadian palsu.
- Rebuild baseline (`POST /api/v1/baseline/update`) kini menolak dengan 409
  beserta daftar `quarantined_files` bila masih ada berkas dikarantina.
  Sebelumnya rebuild diam-diam menghapus berkas yang dikarantina dari
  baseline, lalu pelepasannya dilaporkan sebagai CREATED dan dikarantina
  ulang — operator mengira pelepasan gagal.
- Logout mencabut sesi itu di sisi server (denylist `jti`, bucket
  `revoked_tokens` — bucket keenam Bbolt, di luar hash-chain).
- `POST /api/v1/setup` dan `POST /api/v1/setup/auditor` menolak username
  kosong dan password di luar 8–72 karakter (sebelumnya setup dengan
  username kosong dapat mengunci akun selamanya: password tersimpan, setup
  menolak 403, tetapi tidak ada username yang bisa login).
- `telegram_chat_id` kini mengikuti aturan pointer yang sama dengan
  `backup_webhook_url` (nil = biarkan, string kosong = hapus); sebelumnya
  chat ID tidak pernah bisa dikosongkan dari UI.
- Preflight OPTIONS kini melewati rate limit umum (sebelumnya lolos).
- HSTS dikirim bila request tiba lewat TLS langsung, atau bila
  `FIM_TRUST_PROXY=1` dan `X-Forwarded-Proto: https` diterima. Apakah
  Cloudflare Tunnel meneruskan header itu ke backend diverifikasi saat
  deploy; bila tidak, HSTS tetap menjadi tanggung jawab edge Cloudflare
  (lihat §Deployment).
- Pesan galat pelepasan karantina tidak lagi membocorkan teks galat OS ke
  klien (galat lengkap tetap di log server).
- Berkas non-kode >50 MB yang dilewati kini dihitung di metrik
  `skipped_oversize` dan dicatat di log (sebelumnya sepenuhnya diam).
- `netguard` kini juga menolak `240.0.0.0/4` (reserved).
- Kode mati yang dihapus: `ledger.GetAnomalyCount`/`GetBaselineTime`,
  `config.Get()`, `middleware.JWTAuth`/`ValidateRequest`,
  `helpers.isInternalIP`, `Scanner.CollectFiles`/`IsScanning`/`OnAnomaly`,
  `metrics.Cycle.memPre`. `mem_alloc_bytes` adalah alokasi heap Go pada
  AKHIR siklus, bukan alokasi selama siklus — penamaan metriknya diperbaiki
  di dokumentasi ini agar tidak disalahartikan.

## Pengerasan v1.4.0

- Webhook backup: client HTTP tidak lagi mengikuti redirect (redirect
  307/308 dapat meneruskan body export ledger ke host lain), URL
  divalidasi ulang sesaat sebelum pengiriman, dan koneksi dibuat lewat
  dialer yang menolak alamat non-publik (loopback, privat, link-local,
  multicast, CGNAT `100.64.0.0/10`, `192.0.0.0/24`, benchmarking).
  Sisa risiko di v1.4.0 — DNS dapat berubah antara validasi dial dan
  koneksi (jendela milidetik), dan POST webhook tidak membawa tanda tangan
  — keduanya DITUTUP di v1.5.0: dial memakai literal IP hasil satu kali
  resolve, dan webhook membawa HMAC-SHA256 bila `FIM_WEBHOOK_SECRET`
  di-set (lihat §Backup & notifikasi).
- Rate limit login terpisah (10/menit/IP) dan `FIM_TRUST_PROXY` untuk
  deployment di belakang reverse proxy (lihat §Sesi dan autentikasi).
  IP klien diambil dari `CF-Connecting-IP` dulu (Cloudflare Tunnel),
  lalu `X-Forwarded-For` yang sudah ditimpa Nginx.
- CORS dan pemeriksaan Origin kini fail-closed bila `allowed_origins`
  kosong: tanpa allowlist, hanya same-origin yang lolos.
- Invalidasi sesi: pergantian kredensial menaikkan `session_epoch` dan
  membatalkan semua token lama. Logout tetap hanya menghapus cookie.
- Release karantina kini me-resolve symlink pada target dan watch path
  sebelum memeriksa batas path.
- File non-kode di atas 50 MB tidak lagi hilang diam-diam dari hasil scan:
  ia dilaporkan sebagai dilewati karena batas ukuran dan TIDAK dianggap
  DELETED bila sebelumnya ada di baseline (juga bukan UNREADABLE — isinya
  memang tidak diperiksa; lihat §Batasan).
- `UpdateSettings` parsial tidak lagi menghapus `backup_webhook_url` bila
  field itu tidak dikirim (nil = biarkan, string kosong = hapus). Sejak
  v1.5.0 aturan yang sama berlaku untuk `telegram_chat_id`.
- `StartMonitoring` menjepit interval di bawah 30 detik ke 30 detik, bukan
  diam-diam ke 300 detik. Perbandingan baseline memakai `worker_count`
  konfigurasi (sebelumnya hardcode 4 goroutine).
- Generator secret JWT gagal boot bila generator acak OS gagal (tidak ada
  lagi nilai fallback yang dapat ditebak); nilai fallback lama masuk daftar
  secret lemah sebagai jaring pengaman.
- Password hanya diterima bila tersimpan sebagai hash bcrypt (jalur
  fallback plaintext dihapus); username dibandingkan dalam waktu konstan;
  percobaan login gagal/sukses dicatat di log (tanpa password).
- `GET /api/v1/settings` menyembunyikan `telegram_chat_id` dan
  `backup_webhook_url` dari Auditor.
- Env override baru: `FIM_SCAN_INTERVAL_SEC`, `FIM_WORKER_COUNT`,
  `FIM_BACKUP_WEBHOOK_URL` (URL webhook yang tidak valid membuat boot
  gagal — fail-closed).

## Latensi deteksi: polling, bukan real-time

Deteksi berjalan per siklus polling (`filepath.Walk` + `time.Ticker`,
default kode 300 detik, minimal 30 detik, maksimal 86400 detik).
`data/config.example.json` dan deployment produksi memakai 120 detik, jadi
jeda deteksi maksimum di produksi adalah satu interval 120 detik DITAMBAH
durasi satu siklus scan (sekitar 1 detik pada simulasi v1.2.0 dengan 3901
berkas). Siklus pertama langsung berjalan saat monitoring dimulai, lalu
mengikuti ticker. Yang real-time adalah pembaruan dashboard SETELAH
deteksi, lewat SSE (`/api/v1/events`). Naskah dan presentasi harus memakai
istilah ini secara tepat: "deteksi polling deterministik, notifikasi
dashboard real-time via SSE", bukan "deteksi real-time".

## Deployment Linux dengan systemd

Template tersedia di `deploy/fim-ipl.service` dan contoh secret tersedia di
`deploy/fim-ipl.env.example`.

Contoh alur deployment:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin fim-ipl
sudo install -d -o fim-ipl -g fim-ipl -m 0700 /opt/fim-ipl/data
sudo install -d -o root -g root -m 0700 /etc/fim-ipl
sudo install -o root -g root -m 0600 deploy/fim-ipl.env.example /etc/fim-ipl/fim.env
sudo install -o root -g root -m 0644 deploy/fim-ipl.service /etc/systemd/system/fim-ipl.service
# Salin config contoh dan sesuaikan watch_paths / scan_interval_sec /
# allowed_origins dengan server ini (default contoh: 120 detik).
sudo install -o fim-ipl -g fim-ipl -m 0600 data/config.example.json /opt/fim-ipl/data/config.json
go build -o /tmp/fim-ipl ./cmd/server
sudo install -o root -g root -m 0755 /tmp/fim-ipl /opt/fim-ipl/fim-ipl
sudo systemctl daemon-reload
sudo systemctl enable --now fim-ipl
sudo systemctl status fim-ipl
```

Sebelum menjalankan, edit `/etc/fim-ipl/fim.env` dan ganti seluruh nilai
contoh. File tersebut harus dimiliki `root:root` dengan mode `0600`.

Setelah service berjalan: `POST /api/v1/setup` (buat admin pertama, bila
`FIM_ADMIN_PASSWORD` tidak di-set), lalu login dan `POST
/api/v1/baseline/init` + `POST /api/v1/monitoring/start`. Tanpa langkah ini
daemon boot dengan config hasil auto-generate (JWT secret acak, watch path
kosong, admin belum ada) dan monitoring tidak berjalan.

Perhatian pada unit systemd (`deploy/fim-ipl.service`):

- Karantina membutuhkan `CAP_FOWNER` dan `SupplementaryGroups` berisi grup
  user web server (di Ubuntu + WordPress: `www-data`), plus setiap watch
  path di `ReadWritePaths` — tanpa itu, `ProtectSystem=strict` me-mount
  filesystem read-only dan karantina gagal (bug yang ditemukan saat
  simulasi 2026-10-29). Sesuaikan ketiganya bila watch path atau user web
  berbeda.
- Template mengaktifkan `FIM_REQUIRE_EXTERNAL_SECRETS=1` (semua kredensial
  lewat environment). Deployment yang memakai Settings API untuk Telegram /
  Auditor harus MEMATIKAN flag itu di unit service dan di `fim.env`,
  karena Settings API menulis kredensial ke `config.json` — bila flag
  tetap aktif, boot gagal by design. Produksi TPQ Al-Fawwaz memakai varian
  kedua (flag mati; `config.json` 0600 milik `fim-ipl` adalah sumber
  kebenaran runtime untuk Telegram dan Auditor, sementara JWT secret dan
  password admin tetap dari `fim.env`).
- `FIM_TRUST_PROXY=1` ada di `deploy/fim-ipl.env.example`. Aktifkan hanya
  bila Nginx di depan backend MENIMPA `X-Forwarded-For` dengan
  `$remote_addr` (lihat contoh di bawah) dan trafik publik hanya datang
  lewat Cloudflare Tunnel. Perhatian: di deployment ini `$remote_addr`
  Nginx selalu `127.0.0.1` (cloudflared lokal), jadi IP klien asli BUKAN
  dari `X-Forwarded-For`, melainkan dari `CF-Connecting-IP` yang ditulis
  ulang edge Cloudflare — backend memakai header itu dulu. Jangan menimpa
  atau menghapus `CF-Connecting-IP` di Nginx. Bila Nginx meneruskan header
  klien apa adanya, penyerang dapat memalsukan IP dan melewati rate limit.

### Nginx / dashboard / Cloudflare (di luar repo ini)

Repo ini tidak memuat konfigurasi Nginx, PM2, maupun Cloudflare Tunnel.
Deployment produksi TPQ Al-Fawwaz memakai pola berikut (contoh, sesuaikan
domain dan port):

```nginx
# Dashboard (PM2 serve dist/ di 127.0.0.1:3001) dan API (127.0.0.1:8080)
# dalam satu origin yang sama, agar cookie sesi tidak butuh CORS.
location / {
    proxy_pass http://127.0.0.1:3001;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;  # TIMPA, jangan append
}
location /api/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;  # TIMPA, jangan append
    proxy_buffering off;   # wajib untuk SSE /api/v1/events
    proxy_cache off;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

HTTPS dan HSTS ditangani Cloudflare di depan Nginx. Sejak v1.5.0 backend
juga mengirim `Strict-Transport-Security` bila request tiba lewat TLS
langsung, atau bila `FIM_TRUST_PROXY=1` dan header `X-Forwarded-Proto:
https` diterima. Apakah Cloudflare Tunnel meneruskan header itu ke backend
diverifikasi saat deploy (periksa header respons API); bila tidak, HSTS
tetap menjadi tanggung jawab edge Cloudflare — backend tidak mengklaim
HSTS aktif tanpa bukti itu. `CF-Connecting-IP` diteruskan Nginx apa adanya
(header klien biasa, bukan hop-by-hop) dan dipakai backend sebagai IP
klien bila `FIM_TRUST_PROXY=1`.

### Batas Keamanan yang Jelas

- Jika user web seperti `www-data` terkena compromise, user tersebut tidak
  boleh dapat membaca `/etc/fim-ipl/fim.env`, `/opt/fim-ipl/data`, atau proses
  FIM. Daemon tetap berjalan sebagai `fim-ipl` dan mendeteksi perubahan webroot.
- Jika user `fim-ipl` terkena compromise, hentikan service, cabut semua secret,
  simpan backup ledger off-host, dan rebuild host.
- Jika `root` terkena compromise, semua file dan proses lokal dapat dibaca atau
  diubah. Aplikasi tidak dapat menjamin integritas lokal lagi. Lakukan rebuild
  host, rotasi credential, review firewall/egress, dan gunakan EDR/telemetri
  host.

Menyembunyikan atau mengganti nama `config.json` bukan kontrol keamanan.
Kontrol yang benar adalah permission, user OS terpisah, secret eksternal,
localhost binding, dan backup off-host.

### Batas sumber daya systemd (v1.6.0, T-08)

Sebelumnya unit systemd tidak punya batas apa pun: angka memori di naskah
hanya klaim, bukan penegakan. Unit repo kini menetapkan:

- `MemoryMax=256M` — daemon yang lepas kendali (mis. kebocoran memori
  saat scan) tidak bisa menekan PHP-FPM sampai situs mati.
- `CPUWeight=10` dan `Nice=10` — bila CPU diperebutkan, scheduler
  mendahulukan PHP-FPM.
- `IOSchedulingClass=idle` — I/O scan mengalah pada I/O web.

Batas ini **diukur, bukan ditebak** (5 Nov 2026, 23:32–23:39 WIB,
instance uji terpisah dengan salinan 3.901 berkas produksi, 1 vCPU,
2 GB RAM; produksi tidak disentuh):

| Ukuran | Hasil |
|---|---|
| RSS daemon saat scan 3.901 berkas (100 sampel/detik) | min 17,8 MB, rata-rata 20,8 MB, maks 21,9 MB |
| RSS daemon produksi (di antara siklus) | 23,4 MB |
| HeapAlloc Go di akhir siklus | 4,4–8,8 MB |
| Durasi satu siklus scan 3.901 berkas | 881–1.307 ms (~1 detik) |
| CPU daemon saat scan | puncak 52–71% dari 1 vCPU selama ~1 detik |
| Latensi WordPress (probe bootstrap PHP-FPM, 100 request) | rata-rata 17 ms, p95 28 ms, maks 119 ms |
| Latensi WordPress selama siklus scan (n=4) | rata-rata 47 ms, maks 61 ms |
| Latensi WordPress selama siklus produksi (n=1) | 14 ms (tidak ada perlambatan terukur) |

MemoryMax=256M memberi ruang ~11x dari RSS maksimum yang terukur
(23,4 MB) dengan tetap menjadi batas nyata. Efek scan terhadap WordPress
terukur dalam puluhan milidetik dan hanya selama ~1 detik per siklus
(120 detik di produksi) — tetapi sampel "selama siklus" memang sedikit
(n=4 dan n=1) karena jendelanya hanya ~1 detik; klaim yang jujur adalah
efeknya kecil, bukan nol. Skala ~20.000 berkas belum diuji (bagian dari
paket bukti v1.6.0).

Unit repo sudah lolos `systemd-analyze verify` (tidak ada keluhan untuk
unit ini). **Penerapan ke unit produksi butuh persetujuan eksplisit**
(edit unit + `daemon-reload` + restart) — belum dilakukan. Bila daemon
mati karena OOM (exit 137 / "memory cgroup out of memory" di journal),
naikkan MemoryMax setelah mengukur ulang — jangan menghapus batasnya.

## API Utama

Base URL: `http://127.0.0.1:8080/api/v1`. Rate limit umum 60 request/menit
per-IP (burst 60); SSE `/events` tidak dihitung; ukuran body request
dibatasi 1 MB untuk SEMUA request (bukan hanya mutasi). Login dan setup
awal memakai limiter terpisah 10 request/menit per-IP.

| Method | Endpoint | Akses | Keterangan |
| --- | --- | --- | --- |
| GET | `/healthz` | Publik | Liveness (status, versi, uptime) |
| POST | `/secure-gate` | Publik | Login; JWT hanya di cookie HttpOnly `fim_session`, bukan di body. Path default, dapat diubah lewat `login_path` di `config.json` (frontend meng-hardcode `/secure-gate`, jadi perubahan itu merusak login dashboard kecuali frontend ikut diubah) |
| POST | `/setup` | Publik, sekali saja | Buat Super Admin pertama; 403 bila admin sudah ada; username wajib, password 8–72 karakter (400 bila tidak memenuhi) |
| POST | `/setup/auditor` | Super Admin | Buat/rotasi akun Auditor; username wajib, password 8–72 karakter |
| GET | `/auth/me` | Auditor + Super Admin | Identitas pemilik cookie sesi |
| POST | `/auth/logout` | Auditor + Super Admin | Hapus cookie sesi; sejak v1.5.0 sesi ini juga dicabut di server (denylist `jti`) |
| GET | `/dashboard/stats` | Auditor + Super Admin | Ringkasan baseline/anomali. Definisi: `safe_files` = berkas baseline yang saat ini TIDAK dikarantina (bukan bukti bersih); `total_anomalies` = jumlah kumulatif sepanjang waktu dari blok anomali (semua aksi kecuali `RELEASED`, termasuk `MODE_CHANGED` dan `UNREADABLE`); `total_blocks` mencakup `RELEASED`; `quarantined_files` = jumlah berkas yang sedang dikarantina |
| GET | `/dashboard/status` | Auditor + Super Admin | Status monitoring/maintenance |
| GET | `/ledger/blocks` | Auditor + Super Admin | Audit block terpaginasikan |
| GET | `/ledger/verify` | Auditor + Super Admin | Verifikasi hash-chain |
| GET | `/ledger/export` | Auditor + Super Admin | Export ledger JSON |
| GET | `/metrics` | Auditor + Super Admin | Metrik scan |
| GET | `/system/info` | Auditor + Super Admin | Versi, OS, worker, interval, watch path |
| GET | `/events` | Auditor + Super Admin | SSE pembaruan dashboard (maks. 4 stream per IP, 64 total) |
| GET | `/settings` | Auditor + Super Admin | Baca konfigurasi (Auditor tidak menerima `telegram_chat_id` dan `backup_webhook_url`) |
| POST | `/settings` | Super Admin | Ubah konfigurasi |
| POST | `/monitoring/start` | Super Admin | Mulai monitoring; 409 bila sudah berjalan atau baseline kosong |
| POST | `/monitoring/stop` | Super Admin | Hentikan monitoring |
| POST | `/maintenance/enable` | Super Admin | Jeda scan dan karantina |
| POST | `/maintenance/disable` | Super Admin | Lanjutkan operasi |
| POST | `/baseline/init` | Super Admin | Buat baseline |
| POST | `/baseline/update` | Super Admin | Perbarui baseline; 409 beserta daftar `quarantined_files` bila masih ada berkas dikarantina (sejak v1.5.0) |
| GET | `/quarantine/list` | Auditor + Super Admin | Berkas yang sedang dikarantina |
| POST | `/quarantine/release` | Super Admin | Release dengan audit block; pesan galat ke klien generik sejak v1.5.0 |
| POST | `/backup/run` | Super Admin | Backup ledger manual; gagal hanya bila Telegram dan webhook sama-sama gagal |
| POST | `/telegram/test` | Super Admin | Kirim pesan uji Telegram; body opsional `telegram_token`/`telegram_chat_id` untuk menguji nilai yang belum disimpan |

Catatan mode kegagalan dan paginasi: `/ledger/blocks` default limit 20,
maks. 100; `/metrics` default limit 100, maks. 1000; metrik disimpan
maks. 5000 siklus dan export ledger memuat 500 metrik terakhir.
`mem_alloc_bytes` pada metrik adalah alokasi heap Go pada AKHIR siklus,
bukan alokasi selama siklus. Webhook backup mengirim header
`X-FIM-IPL-File` dan, bila `FIM_WEBHOOK_SECRET` di-set,
`X-FIM-IPL-Signature` + `X-FIM-IPL-Timestamp` (lihat §Backup &
notifikasi).

Semua endpoint mutasi membutuhkan Super Admin, kecuali `POST
/auth/logout` (semua role yang login) dan `POST /setup` (publik, hanya
sebelum admin dibuat). Auditor bersifat read-only.

## Simulasi Serangan

Script simulasi tersedia di `scripts/` dan payloadnya sengaja jinak. Script
tidak menjalankan RCE, tidak menghubungi C2, dan hanya membuat marker file.

### Linux

```bash
scripts/attack_sim.sh /tmp/fim-test
# jalankan POST /baseline/init setelah setup
scripts/attack_sim.sh /tmp/fim-test --spread --count 25 --symlink
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\attack_sim.ps1 -TargetDir C:\fim-test
# jalankan POST /baseline/init setelah setup
powershell -ExecutionPolicy Bypass -File .\scripts\attack_sim.ps1 -TargetDir C:\fim-test -Spread -Count 25
```

Skenario `--spread`/`-Spread` menguji:

- backdoor di banyak folder bertingkat;
- double extension seperti `avatar.php.jpg`;
- `.htaccess` dan file konfigurasi tersembunyi;
- timestamp spoofing;
- file baru, file berubah, dan file dihapus;
- file tidak terbaca dan symlink bila platform mengizinkan.

## Simulasi Beban

Repo ini TIDAK memuat generator beban/file dummy (tidak ada
`scripts/gen_dummy_files.*`). Bila pengujian beban diperlukan, hasilkan file
uji dengan perkakas OS (mis. `dd`/`fsutil`) di direktori uji yang terpisah,
lalu urutannya: generate file, `baseline/init`, jalankan monitoring, catat
endpoint `/metrics`, lalu bersihkan direktori uji. Jangan memasukkan file
dummy ke baseline produksi. Angka beban yang dikutip di naskah harus berasal
dari pengujian yang benar-benar dijalankan, bukan dari contoh perintah di
dokumen ini.

## Testing dan Quality Gate

```bash
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

`go test -race` membutuhkan toolchain Linux native dengan CGO dan GCC.
Kualitas repository dianggap siap bila seluruh command tersebut lolos.
Sebelum rilis, jalankan juga `govulncheck ./...` pada toolchain yang sama
dengan produksi dan catat hasilnya di pesan commit. Hasil `govulncheck`
v1.5.0 (govulncheck v1.9.0, toolchain go1.27.3, 2026-11-05): 0 vuln yang
memengaruhi kode; 0 di paket yang diimpor; 1 vuln di modul yang dibutuhkan
(`x/crypto`) tetapi tidak dipanggil kode ini — sama seperti v1.4.0.
Dokumen ini tidak mengklaim "bebas vuln" secara absolut — yang diklaim
hanya hasil pemindaian itu.

## Batasan yang Harus Dipahami

- Polling tidak melihat perubahan yang terjadi dan selesai di antara dua siklus.
- TOCTOU antara hashing dan quarantine masih mungkin pada attacker tingkat host.
- Hardlink tidak dapat dibedakan sempurna dari file biasa oleh scanner portable.
- Windows memakai ReadOnly best-effort, bukan permission `000` penuh.
- Telegram memiliki retry sementara, tetapi belum memiliki outbox persisten.
- Backup off-host wajib dipakai untuk mendeteksi penghapusan tail ledger.
- File non-kode di atas 50 MB tidak di-hash dan tidak dilaporkan sebagai
  anomali; bila sebelumnya ada di baseline, file itu tidak dianggap
  terhapus (bukan DELETED, bukan UNREADABLE) — isinya memang tidak
  diperiksa. File kode (termasuk double extension `.php.*`) tetap dipindai
  berapa pun ukurannya. Jumlah berkas yang dilewati tercatat di metrik
  `skipped_oversize` setiap siklus (sejak v1.5.0).
- Logout mencabut sesi itu di sisi server (denylist `jti`) sejak v1.5.0;
  token yang diterbitkan sebelum v1.5.0 (tanpa `jti`) hanya batal bila
  kredensial diubah (yang menaikkan `session_epoch`).
- POST webhook backup membawa tanda tangan HMAC-SHA256 bila
  `FIM_WEBHOOK_SECRET` di-set; tanpa secret, penerima tidak dapat
  membedakan export asli dari POST palsu. Validasi URL dilakukan saat
  menyimpan, saat boot, dan sesaat sebelum pengiriman, redirect tidak
  diikuti, dan dial memakai literal IP hasil satu kali resolve — jendela
  DNS rebinding antara validasi dial dan koneksi sudah ditutup di v1.5.0.
- Token bot Telegram dikirim sebagai bagian dari path URL Bot API oleh
  desain Telegram sendiri; galat transport di-redact agar token tidak
  bocor ke log, tetapi token yang pernah dibagikan (mis. ditempel di chat)
  harus dirotasi lewat BotFather setelah demo skripsi.
- Direktori yang berupa symlink TIDAK pernah ditelusuri (Walk memakai
  Lstat): perubahan di dalam subtree symlink tidak terdeteksi, dan
  dedup membungkamnya agar tidak membanjiri ledger. Ini batasan yang
  didokumentasikan, bukan yang diikuti diam-diam — jangan mengandalkan
  pemantauan lewat symlink direktori.
- Formula hash blok menggabungkan field dengan pemisah `|` tanpa escaping;
  secara teoretis dua kombinasi field berbeda dapat menghasilkan string
  pra-hash yang sama bila path mengandung `|`. Praktiknya dapat diabaikan
  (penyerang perlu mengendalikan path dan hash), dan formula TIDAK diubah
  di v1.4.0 karena mengubahnya akan membuat seluruh blok ledger yang sudah
  ada gagal verifikasi. Demikian pula `quarantine_err` tidak masuk material
  hash blok (hanya flag `quarantined` yang di-hash).
