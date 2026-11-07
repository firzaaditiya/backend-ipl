# Tabel Perubahan v1.3.0 → v1.6.0

Perubahan sistem antara versi yang didokumentasikan di naskah v4
(v1.3.0) dan versi beku v1.6.0 (dalam pengerjaan). Setiap baris memuat
UJ yang membuktikannya. Penomoran KF baru untuk v1.6.0 belum ditetapkan
— itu keputusan penulis naskah (Firza); tabel ini memakai nomor UJ
sebagai jangkar.

## Riwayat versi

| Versi | Tanggal | Perubahan utama | UJ |
|---|---|---|---|
| v1.3.0 | 31 Okt 2026 | `GET /quarantine/list` (Auditor boleh), field `restored_mode` pada Release, panel berkas dikarantina di dasbor | UJ-01–UJ-12 |
| v1.4.0 | 5 Nov 2026 | `internal/netguard` (validasi URL publik, tanpa redirect), `FIM_TRUST_PROXY` + CF-Connecting-IP, pembatas login 10/menit/IP, CORS/CSRF fail-closed, `session_epoch`, logging percobaan login, bcrypt-only, JWT tanpa secret cadangan, batas berkas non-kode >50 MB, `go.mod` 1.26.0 | UJ-02–UJ-04, UJ-06, UJ-08 (diulang) |
| v1.5.0 | 5 Nov 2026 | Deteksi MODE_CHANGED, paket `internal/fsx` (chmod tanpa-follow lewat `/proc/self/fd`), HMAC webhook + guarded dial, denylist `jti` saat logout, alert Telegram asinkron, `baseline/update` 409 bila ada karantina, HSTS di tepi, axios 1.21.0 + vite 8.3.6 | UJ-13 |
| v1.6.0 (T-01) | 5 Nov 2026 | Verifikasi karantina per siklus; aksi baru QUARANTINE_BREACH + karantina ulang otomatis + alert URGENT | UJ-14 |
| v1.6.0 (T-02) | 5 Nov 2026 | Formula hash blok v2 (length-prefixed, mencakup mode + Actor + Detail); rantai campuran v1→v2 valid | (bagian dari UJ-14–UJ-19) |
| v1.6.0 (T-03) | 5 Nov 2026 | 8 aksi admin masuk ledger; alasan wajib 1–500 karakter pada release + baseline/update; Actor "username (Peran) dari IP" | (bagian dari UJ-14–UJ-19) |
| v1.6.0 (T-04) | 5 Nov 2026 | Formula hash blok v3 (+ BaselineDigest + BaselineCount); `GET /ledger/verify-baseline`; mode pemulihan dari rantai | UJ-16 |
| v1.6.0 (T-05) | 5 Nov 2026 | `exclude_globs` + kebijakan uploads bawaan (non-kode dikecualikan, berkas mirip-kode tetap dipantau); metrik `excluded_files` | UJ-15 |
| v1.6.0 (T-06) | 5 Nov 2026 | Jangkar di setiap alert Telegram; verifikasi terjadwal (1 menit setelah boot, lalu tiap jam) + `last_verified` di dasbor; verifier mandiri `cmd/verify` (fim-verify) | UJ-17 |
| v1.6.0 (T-07) | 5 Nov 2026 | Secret Telegram dari `fim.env` (FIM_REQUIRE_EXTERNAL_SECRETS=1); hash bcrypt auditor diizinkan di `config.json`; bug Load (secret acak tertulis ke disk) diperbaiki; unit systemd repo disinkronkan | UJ-18 |
| v1.6.0 (T-08) | 5 Nov 2026 | Batas sumber daya systemd: MemoryMax=256M, CPUWeight=10, Nice=10, IOSchedulingClass=idle + pengukuran | UJ-19 |

## Perubahan definisi dasbor

| Definisi | v1.3.0–v1.5.0 | v1.6.0 | Dampak |
|---|---|---|---|
| `total_anomalies` | Menghitung semua blok kecuali RELEASED (termasuk MODE_CHANGED) | Hanya aksi anomali pemindaian (CREATED, MODIFIED, MODE_CHANGED, QUARANTINE_BREACH, DELETED, UNREADABLE); RELEASED dan aksi admin tidak dihitung | Angka setelah v1.6.0 TIDAK bisa dibandingkan mentah dengan angka v1.0–v1.5.0 tanpa catatan ini |
| `excluded_files` | Tidak ada | Jumlah berkas yang dikecualikan pada siklus terakhir (dari metrik terbaru) | Baru (T-05) |
| `last_verified` | Tidak ada | Waktu verifikasi terjadwal terakhir + status rantai + head block | Baru (T-06) |
| Panel karantina | Daftar berkas dikarantina | Menandai MERAH bila `current_mode` bukan 000 | Baru (T-01) |
| `safe_files` | `total_files − quarantined_files` | Tidak berubah (tetap "tidak sedang dikarantina", BUKAN "terbukti bersih") | — |

## Perubahan skema ledger

| Bidang / aksi | v1.3.0–v1.5.0 | v1.6.0 |
|---|---|---|
| `hash_version` | Tidak ada (implisit v1) | 0/absen = v1; 2 = v2 (T-02); 3 = v3 (T-04). Tidak ada versi 1. Setiap formula yang sudah didefinisikan TIDAK PERNAH diubah. |
| `actor`, `detail` | Tidak ada | Ditambahkan di v2 (diisi T-03) |
| `baseline_digest`, `baseline_count` | Tidak ada | Ditambahkan di v3 (T-04); hanya blok BASELINE_INIT/UPDATE yang membawanya |
| Aksi baru | — | QUARANTINE_BREACH (T-01); BASELINE_INIT, BASELINE_UPDATE, MONITORING_START, MONITORING_STOP, MAINTENANCE_ON, MAINTENANCE_OFF, SETTINGS_CHANGED, AUDITOR_SET (T-03) |
| `quarantine_modes` (bucket) | Satu-satunya sumber mode pemulihan | Hanya fallback; mode pemulihan kini bersumber dari rantai (blok karantina terakhir) (T-04) |
| Kompatibilitas | — | Rantai campuran v1→v2→v3 terverifikasi valid di instance uji; 29 blok produksi v1 tetap valid karena formula v1 tidak berubah |

## Perubahan API

| Endpoint | Perubahan |
|---|---|
| `GET /api/v1/ledger/verify-baseline` | Baru (T-04); read-only, Auditor boleh |
| `GET /api/v1/dashboard/status` | Tambah `last_verified` (T-06) |
| `GET /api/v1/dashboard/stats` | Tambah `excluded_files` (T-05) |
| `POST /api/v1/quarantine/release` | Alasan wajib 1–500 karakter (T-03); respons membawa `"audited"` |
| `POST /api/v1/baseline/update` | Alasan wajib (T-03); 409 bila ada berkas dikarantina (sejak v1.5.0) |
| `POST /api/v1/settings` | Menolak perubahan Telegram bila sumbernya env (400) (T-07); `GET /settings` mengembalikan `telegram_token_from_env` / `telegram_chat_id_from_env` |
| Semua mutasi | Respons membawa `"audited"` (T-03) |
| Jumlah rute | 26 (v1.5.0) → 27 (v1.6.0) |

## Yang sengaja TIDAK diubah

- Formula hash blok v1 (29 blok produksi tetap terverifikasi).
- Karantina tetap `chmod 000` tanpa menghapus; deteksi tetap polling
  deterministik (tanpa inotify); ledger tetap SHA-256 hash-chain di
  Bbolt; auth tetap kuki HttpOnly tanpa Bearer.
- HMAC blok TIDAK ditambahkan (kunci di server yang sama tidak
  menghentikan root — T-06).
- Tidak ada klasifikasi malware/konten, tidak ada IDS/IPS, tidak ada
  pemulihan konten otomatis (batas scope brief).
