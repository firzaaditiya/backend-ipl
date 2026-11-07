# Paket Bukti v1.6.0 — `docs/evidence/`

Paket bukti yang dapat direproduksi untuk versi beku v1.6.0. Tidak ada
secret di dalam paket ini (token, password, dan JWT secret tidak pernah
masuk ke berkas bukti).

## Isi

| Berkas | Isi |
|---|---|
| `README.md` (ini) | Indeks paket, matriks KF → UJ, dan cara mereproduksi |
| `uj_matrix.csv` | Matriks KF/NKF → UJ → bukti (satu baris per UJ, dengan versi + waktu + tiga sisi bukti: respons API, `stat` disk, blok ledger). Baris UJ-01–UJ-19 memuat catatan "RUN BEKU v1.6.0" hasil uji ulang 7 Nov 2026; baris UJ-20 (format Telegram minimal) ditambahkan pada run beku. |
| `uj_latency.csv` | Hasil benchmark latensi deteksi (30 repetisi per tipe event, fase acak). Kolom `run` membedakan run1 (ronde P0, 5 Nov 2026, binary dev) dan run2 (binary beku v1.6.0, 7 Nov 2026). |
| `uj_resources.csv` | Hasil benchmark sumber daya (RSS, CPU, durasi siklus, latensi WordPress). Run4 = 3.901 berkas beku, run5 = ~20.000 berkas beku (7 Nov 2026). |
| `uj_ledger_limits.md` | Hasil uji batas ledger (pemotongan ekor, perusakan OldMode, perusakan baseline, jangkar eksternal) |
| `config_facts.md` | Fakta konfigurasi nyata (ter-redaksi): struktur `config.json` produksi, unit systemd, aturan port Nginx |
| `change_table_v130_to_v160.md` | Tabel perubahan v1.3.0 → v1.6.0 (KF, UJ, definisi dasbor — terutama "Anomalies" — dan skema ledger) |
| `honesty_notes.md` | Batas yang tersisa (root, polling, TOCTOU, hardlink, direktori symlink, non-kode >50 MB, Telegram) |

## Matriks KF → UJ

Sumber kebenaran matriks adalah
`~/workspace/skripsi/BAB-IV-bukti-pengujian.md` (peta bukti Bab IV).
`uj_matrix.csv` adalah salinan yang dapat dibaca mesin dari peta itu,
satu baris per UJ:

- **UJ-01–UJ-12**: bukti produksi atau salinan ekspor (v1.0–v1.3.0).
- **UJ-13**: MODE_CHANGED (v1.5.0, produksi).
- **UJ-14**: QUARANTINE_BREACH (v1.6.0, T-01, instance uji).
- **UJ-15**: pengecualian `exclude_globs` + kebijakan uploads (v1.6.0, T-05, instance uji).
- **UJ-16**: digest baseline + `verify-baseline` (v1.6.0, T-04, instance uji).
- **UJ-17**: jangkar eksternal + verifikasi terjadwal + `fim-verify` (v1.6.0, T-06, instance uji).
- **UJ-18**: manajemen secret produksi (v1.6.0, T-07, instance uji; langkah produksi menunggu persetujuan).
- **UJ-19**: batas sumber daya systemd + pengukuran (v1.6.0, T-08, instance uji + baca produksi).
- **UJ-20**: format Telegram minimal (v1.6.0, T-13, instance uji + unit test + render dari ledger nyata + pengiriman nyata).

## Cara mereproduksi

Semua pengujian dijalankan di instance uji terpisah
(`/opt/fim-test-v16`, port 8090, interval 30 dtk), BUKAN di produksi —
kecuali yang eksplisit dinyatakan "produksi" dan hanya membaca
(ekspor ledger, metrik, `stat`).

Skrip di `scripts/`:

- `scripts/uj_latency.sh` — benchmark latensi (D.3): 30 repetisi per
  tipe event dengan fase acak; keluaran CSV + ringkasan.
- `scripts/uj_suite.sh` — (menyusul) menjalankan ulang seluruh UJ
  pada satu versi dan menghasilkan JSON/CSV.

## Status

**BEKU v1.6.0.** Pembekuan 7 Nov 2026: backend `3fe3ed6f53150bb40182c1da95250637ba6c66e4`,
frontend `a57091a81a315a8bbd2e77314f5d4dbcc08629c2`. Gates pada tree beku:
gofmt bersih, `go vet` OK, `go test -race -count=1 ./...` semua paket OK,
govulncheck 0 vulnerabilities, frontend tanpa perubahan (HEAD saja
diverifikasi). Seluruh UJ-01–UJ-20 dijalankan ulang pada SATU binary beku
yang sama (`/opt/fim-test-v16/fim-ipl-160`, dibangun 7 Nov 2026 19:09 WIB
dari backend HEAD 3fe3ed6) di instance uji — hasilnya dicatat sebagai
"RUN BEKU v1.6.0" di `uj_matrix.csv` dan sebagai run2/run4/run5 di CSV
benchmark. Produksi TIDAK disentuh dan masih v1.5.0 (29 blok).

Hasil run beku (7 Nov 2026):

- Latensi deteksi (`uj_latency.csv` run2, 12:33–12:48 UTC, interval 30 dtk,
  30 repetisi per tipe, 0 hilang): CREATED rata-rata 14,9 dtk (p95 26,9;
  maks 28,8); MODIFIED rata-rata 17,0 (p95 27,4; maks 27,8); DELETED
  rata-rata 18,4 (p95 26,8; maks 29,8); MODE_CHANGED rata-rata 15,5
  (p95 27,4; maks 29,8). Teori: rata-rata T/2 = 15 dtk, maks T + durasi
  siklus ~31 dtk — semua maks dalam teori; rata-rata dalam ~3,4 dtk dari
  teori (DELETED 18,4 paling jauh — variasi sampling, dilaporkan apa
  adanya).
- Sumber daya run4 (3.901 berkas, `uj_resources.csv`): RSS 18,1–21,5 MB
  (rata-rata 21,2), siklus 763–975 ms, HeapAlloc 5,67–8,13 MB, CPU maks
  43% dari 1 vCPU (jendela 1 dtk), latensi WP lokal rata-rata 15 ms
  (p95 26 ms), 16 ms selama siklus (n=4). Run5 (~20.000 berkas): RSS
  31,8–58,6 MB (rata-rata 56,4), siklus 4.614–6.443 ms, HeapAlloc
  24,74–32,37 MB, CPU maks 59%, latensi WP lokal rata-rata 18 ms
  (p95 37 ms), 31 ms selama siklus (n=20). Baseline init 1,0 dtk
  (3.901) / 5,8 dtk (20.000); deteksi CREATED pada 19.505 berkas ~13,3
  dtk. MemoryMax=256M = ~12x RSS maks 3.901 berkas, ~4,4x RSS maks
  20.000 berkas. Catatan metode: pengukuran CPU dan WP pada run beku
  pertama memakai jendela sampling 10 ms dan URL publik via Cloudflare
  (keduanya berisik, dibuang); angka di atas adalah pengukuran ulang
  bersih (CPU jendela 1 dtk, WP lokal `http://127.0.0.1/` 301).
- UJ-20 (T-13): format Telegram minimal terverifikasi lewat unit test,
  render dari blok ledger nyata, DAN pengiriman nyata ke chat Firza
  (test message 19:51:53 WIB + 1 alert anomali CREATED 19:56:53 WIB).
- Keadaan akhir instance uji v16: 238 blok, head BLK-000238, rantai
  valid, verify-baseline match (digest e6d1fc2c…, count 2), 0 karantina.

Yang sudah terukur (pra-beku, instance uji):

- Latensi deteksi (`uj_latency.csv`, 5 Nov 2026, 23:46–23:59 WIB,
  interval 30 dtk, 30 repetisi per tipe, fase acak): CREATED
  rata-rata 14,14 dtk (p95 26,36; maks 27,98); MODIFIED rata-rata
  14,18 (p95 27,79; maks 29,79); DELETED rata-rata 15,34 (p95 28,78;
  maks 28,80); MODE_CHANGED rata-rata 14,15 (p95 24,82; maks 27,82).
  Teori: rata-rata T/2 = 15 dtk, maks T + durasi siklus ~31 dtk —
  semua rata-rata dalam 1 dtk dari teori dan tidak ada yang melampaui
  maks teoritis. Catatan run: sesi SSH expect putus pada 600 dtk,
  skrip selamat dan selesai di VPS tetapi mati SIGPIPE saat menulis
  ke pipe yang putus — bersih-bersih dilakukan manual (59 release
  lolos, 31 gagal 429 karena pembatas 60 req/menit, lalu rebuild
  baseline; instance kembali bersih: 9 berkas, 0 karantina,
  verify-baseline match). Skrip sudah diperbaiki (output ke berkas
  log, kunci `file_path`, jeda 1,1 dtk antar release).
  **Mengapa catatan lama menunjukkan delay sampai ~130 dtk padahal
  interval produksi 120 dtk?** Teori: maks = T + durasi siklus +
  pemrosesan per event ≈ 121–122 dtk. Angka 130 dtk berasal dari
  simulasi v1.5.0 yang waktu event-nya dicatat per MENIT ("~17:09"),
  bukan per detik — jadi angka 130 dtk itu sendiri membawa
  ketidakpastian ±30 dtk dan tidak cukup presisi untuk membantah
  teori. Benchmark v1.6.0 ini mencatat waktu event per detik dan
  membenarkan teori: maks 29,79 dtk < 31 dtk untuk T=30 dtk. Dua
  penyumbang kecil lain yang sah: event yang jatuh di tengah jendela
  scan (~1 dtk, setelah walker melewati direktorinya) menunggu siklus
  berikutnya, dan pemrosesan per event dalam satu siklus (chmod
  karantina + fsync Bbolt per event + antrean alert) menambah
  hitungan detik bila beberapa event mendarat dalam satu siklus.
- Sumber daya: RSS daemon 17,8–21,9 MB saat scan 3.901 berkas;
  siklus ~1 dtk; CPU puncak 52–71% dari 1 vCPU; latensi WordPress
  rata-rata 17 ms (p95 28 ms), 47 ms selama siklus sintetik (n=4),
  14 ms selama siklus produksi (n=1). Skala ~20.000 berkas TERUJI
  6 Nov 2026 00:04–00:09 WIB (19.505 berkas, 631 MB): RSS 38,8–62,6
  MB (rata-rata 57,5), siklus 4.382–5.124 ms (~5 dtk), HeapAlloc
  29,0–36,7 MB, CPU puncak 76%, latensi WP rata-rata 20 ms (p95
  56 ms), baseline init 6,9 dtk, deteksi CREATED ~34 dtk; skala
  mendekati linear (5x berkas → ~5x durasi siklus); MemoryMax=256M
  masih memberi ruang ~4x. Pohon uji dipertahankan di
  `/opt/fim-test-20k/www` untuk uji ulang beku.
- Batas ledger: pemotongan ekor TIDAK terdeteksi verifikasi lokal
  (tetap VALID) tetapi TERDETEKSI lewat perbandingan head hash dengan
  jangkar Telegram; perusakan satu blok terdeteksi tepat di blok itu
  (BLK-000011).
