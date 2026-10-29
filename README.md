# FIM-IPL Backend

FIM-IPL Backend adalah daemon File Integrity Monitoring (FIM) dan REST API
untuk memantau perubahan file pada server web. Sistem membandingkan hash
SHA-256 dengan baseline, mencatat kejadian ke Immutable Private Ledger lokal,
menonaktifkan file mencurigakan, dan mengirim notifikasi operasional.

Repository ini mandiri. Semua command, konfigurasi contoh, deployment unit,
dan script simulasi yang diperlukan untuk menjalankan backend ada di dalam
repository ini.

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
      +--> CREATED / MODIFIED --> quarantine --> ledger --> Telegram
      +--> DELETED ------------> ledger -----------------> Telegram
      +--> UNREADABLE ---------> alert + ledger ----------> Telegram
      |
      v
metrics + SSE + dashboard API
```

Scanner menggunakan polling dengan `time.Ticker`, bukan filesystem event
watcher. Pendekatan ini dipilih agar perilaku deterministik, portabel di Linux
dan Windows, serta tidak kehilangan perubahan ketika daemon restart.

## Fitur

- Hash SHA-256 untuk baseline dan perubahan file.
- Worker pool untuk pemindaian paralel.
- Aksi `CREATED`, `MODIFIED`, `DELETED`, dan `UNREADABLE`.
- Karantina Linux dengan `chmod 000`.
- Karantina Windows dengan best-effort ReadOnly attribute.
- Immutable Private Ledger lokal berbasis Bbolt dan hash-chain.
- Verifikasi chain dan external head anchor.
- Export dan backup ledger ke Telegram/webhook.
- Retry Telegram untuk error jaringan, HTTP 429, dan HTTP 5xx.
- JWT HS256, bcrypt, RBAC Super Admin/Auditor, rate limit, CORS, security
  headers, SSRF-safe webhook validation, dan SSE realtime.
- Environment override untuk semua secret deployment.
- Mode strict yang menolak secret di `config.json`.

## Persyaratan

- Go 1.25 atau lebih baru.
- Linux direkomendasikan untuk deployment produksi.
- Windows didukung untuk pengembangan dan simulasi fungsional.
- `curl` untuk health check.
- Telegram Bot API hanya diperlukan jika notifikasi Telegram dipakai.

## Menjalankan Lokal

Salin konfigurasi contoh. File hasil salinan bersifat lokal dan tidak boleh
dimasukkan Git:

```bash
cp data/config.example.json data/config.json
export FIM_CONFIG_PATH="$PWD/data/config.json"
export FIM_JWT_SECRET="buat-rahasia-acak-minimal-32-karakter"
export FIM_ADMIN_PASSWORD="buat-password-admin-kuat"
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
go run ./cmd/server
```

Jangan menjalankan daemon sebagai user web pada deployment produksi.

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
| `FIM_ALLOWED_ORIGINS` | Daftar origin CORS dipisahkan koma |
| `FIM_COOKIE_SECURE` | `1` (default) = cookie sesi memakai atribut Secure; `0` hanya untuk dev HTTP lokal |
| `FIM_STRICT_SECRETS=1` | Tolak JWT secret lemah |
| `FIM_REQUIRE_EXTERNAL_SECRETS=1` | Tolak credential di `config.json` |
| `FIM_REQUIRE_LOCAL_API=1` | Tolak binding API wildcard |

`FIM_REQUIRE_EXTERNAL_SECRETS=1` dan `FIM_REQUIRE_LOCAL_API=1` sebaiknya selalu
dipakai di server produksi, DENGAN satu pengecualian: `FIM_REQUIRE_EXTERNAL_SECRETS=1`
tidak kompatibel dengan penyimpanan Telegram/Auditor lewat Settings API (API itu
memang menulis ke `config.json`). Deployment yang memakai Settings API harus
mematikan flag tersebut dan menerima `config.json` (0600, milik `fim-ipl`)
sebagai sumber kebenaran runtime untuk Telegram dan Auditor, sementara JWT
secret dan password admin tetap dari `fim.env` (environment menang atas
`config.json` saat restart).

## Sesi dan autentikasi (v1.1.0)

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
- CSRF: selain `SameSite=Lax`, request mutasi (`POST`/`PUT`/`DELETE`/`PATCH`)
  diperiksa Origin-nya — lolos bila Origin kosong (curl/alat admin), sama
  dengan Host request (same-origin lewat proxy), atau ada di allowlist.
  Pemeriksaan nonaktif bila allowlist kosong, jadi produksi wajib mengisi
  `allowed_origins` dengan origin dashboard.
- Frontend dan API WAJIB satu origin (proxy Nginx yang sama). Desain ini
  sengaja: tidak ada CORS lintas origin untuk dashboard.

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

## Latensi deteksi: polling, bukan real-time

Deteksi berjalan per siklus polling (`filepath.Walk` + `time.Ticker`,
default 120 detik, minimal 30 detik), jadi jeda deteksi maksimum adalah satu
interval. Yang real-time adalah pembaruan dashboard SETELAH deteksi, lewat
SSE (`/api/v1/events`). Naskah dan presentasi harus memakai istilah ini
secara tepat: "deteksi polling deterministik, notifikasi dashboard real-time
via SSE", bukan "deteksi real-time".

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
go build -o /tmp/fim-ipl ./cmd/server
sudo install -o root -g root -m 0755 /tmp/fim-ipl /opt/fim-ipl/fim-ipl
sudo systemctl daemon-reload
sudo systemctl enable --now fim-ipl
sudo systemctl status fim-ipl
```

Sebelum menjalankan, edit `/etc/fim-ipl/fim.env` dan ganti seluruh nilai
contoh. File tersebut harus dimiliki `root:root` dengan mode `0600`.

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

## API Utama

Base URL: `http://127.0.0.1:8080/api/v1`

| Method | Endpoint | Keterangan |
| --- | --- | --- |
| GET | `/healthz` | Liveness publik |
| POST | `/secure-gate` | Login dan JWT |
| GET | `/dashboard/stats` | Ringkasan baseline/anomali |
| GET | `/ledger/blocks` | Audit block terpaginasikan |
| GET | `/ledger/verify` | Verifikasi hash-chain |
| GET | `/ledger/export` | Export ledger JSON |
| GET | `/metrics` | Metrik scan |
| GET | `/events` | SSE realtime terautentikasi |
| POST | `/baseline/init` | Buat baseline, Super Admin |
| POST | `/baseline/update` | Perbarui baseline, Super Admin |
| POST | `/monitoring/start` | Mulai monitoring |
| POST | `/monitoring/stop` | Hentikan monitoring |
| POST | `/maintenance/enable` | Jeda scan dan karantina |
| POST | `/maintenance/disable` | Lanjutkan operasi |
| POST | `/quarantine/release` | Release dengan audit block |
| POST | `/backup/run` | Backup ledger manual |

Semua endpoint mutasi membutuhkan Super Admin. Auditor bersifat read-only.

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

Generator file dummy tersedia di `scripts/gen_dummy_files.sh` dan
`scripts/gen_dummy_files.ps1`.

```bash
scripts/gen_dummy_files.sh 10000 /tmp/fim-test/loadtest 4
```

Urutan pengujian yang benar: generate file, `baseline/init`, jalankan
monitoring, catat endpoint `/metrics`, lalu bersihkan direktori uji. Jangan
memasukkan file dummy ke baseline produksi.

## Testing dan Quality Gate

```bash
```

`go test -race` membutuhkan toolchain Linux native dengan CGO dan GCC.
Kualitas repository dianggap siap bila seluruh command tersebut lolos.

## Batasan yang Harus Dipahami

- Polling tidak melihat perubahan yang terjadi dan selesai di antara dua siklus.
- TOCTOU antara hashing dan quarantine masih mungkin pada attacker tingkat host.
- Hardlink tidak dapat dibedakan sempurna dari file biasa oleh scanner portable.
- Windows memakai ReadOnly best-effort, bukan permission `000` penuh.
- Telegram memiliki retry sementara, tetapi belum memiliki outbox persisten.
- Backup off-host wajib dipakai untuk mendeteksi penghapusan tail ledger.
