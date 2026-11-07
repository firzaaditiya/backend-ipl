# Paket Bukti v1.6.0 — `docs/evidence/`

Paket bukti yang dapat direproduksi untuk versi beku v1.6.0. Tidak ada
secret di dalam paket ini (token, password, dan JWT secret tidak pernah
masuk ke berkas bukti).

## Isi

| Berkas | Isi |
|---|---|
| `README.md` (ini) | Indeks paket, matriks KF → UJ, dan cara mereproduksi |
| `uj_matrix.csv` | Matriks KF/NKF → UJ → bukti (satu baris per UJ, dengan versi + waktu + tiga sisi bukti: respons API, `stat` disk, blok ledger) |
| `uj_latency.csv` | Hasil benchmark latensi deteksi (30 repetisi per tipe event, fase acak) |
| `uj_resources.csv` | Hasil benchmark sumber daya (RSS, CPU, durasi siklus, latensi WordPress) |
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

**BELUM BEKU.** Paket ini disiapkan sebelum pembekuan v1.6.0. Seluruh
UJ harus dijalankan ulang pada SATU versi beku v1.6.0 setelah Firza
menyetujuinya; angka-angka yang sudah ada (UJ-14–UJ-19 dari instance
uji) adalah bukti ronde pengembangan, bukan bukti versi beku — dan
akan dicatat ulang bila ada perubahan kode antara sekarang dan
pembekuan.

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
