# Catatan Kejujuran — Batas yang Tersisa (v1.6.0)

Batas-batas ini tetap berlaku setelah seluruh P0 (T-01–T-08) selesai.
Ditulis di sini agar tidak ada yang mengklaim lebih dari yang sistem
lakukan — terutama di naskah skripsi.

## Root

- Bila `root` di server dikompromikan, seluruh jaminan lokal runtuh:
  root bisa membaca/mengubah ledger, config, secret, dan binary.
  Satu-satunya deteksi adalah jangkar eksternal (head hash di Telegram
  dan backup off-host) — dan itu pun hanya mendeteksi perubahan yang
  SUDAH terjadi, bukan mencegahnya. Lihat UJ-17 untuk batas
  pemotongan ekor: verifikasi lokal tidak bisa mendeteksi ekor yang
  dipotong; perbandingan dengan jangkar yang bisa.
- HMAC blok sengaja TIDAK ditambahkan (T-06): kunci yang disimpan di
  server yang sama tidak menghentikan root.

## Polling

- Deteksi BUKAN real-time: polling deterministik dengan interval
  (produksi 120 dtk). Perubahan yang terjadi dan selesai di antara dua
  siklus tidak terlihat. Delay deteksi maksimum adalah interval +
  durasi siklus + pemrosesan per event — terukur di `uj_latency.csv`.
- Hanya pembaruan dasbor SSE yang real-time; deteksinya tidak.

## TOCTOU

- Ada jendela TOCTOU antara hashing dan karantina: berkas bisa berubah
  di antara dibaca (hash) dan dikarantina (chmod). Penyerang tingkat
  host bisa memanfaatkannya; ini batasan yang didokumentasikan, bukan
  yang diselesaikan.

## Hardlink dan symlink

- Hardlink tidak dapat dibedakan sempurna dari berkas biasa oleh
  scanner portable.
- Direktori symlink TIDAK pernah ditelusuri (Walk memakai Lstat):
  perubahan di dalam subtree symlink tidak terdeteksi.

## Berkas non-kode >50 MB

- Berkas non-kode di atas 50 MB tidak di-hash dan tidak dilaporkan
  sebagai anomali; bila sebelumnya ada di baseline, berkas itu tidak
  dianggap terhapus. Isinya memang tidak diperiksa. Berkas kode
  (termasuk double extension `.php.*`) tetap dipindai berapa pun
  ukurannya. Jumlah berkas yang dilewati tercatat di metrik
  `skipped_oversize` setiap siklus (sejak v1.5.0).

## Telegram

- Telegram adalah satu-satunya kanal alert dan backup off-host — dan
  token bot-nya pernah ditempel di chat (diperlakukan sebagai bocor;
  rotasi via BotFather belum dilakukan).
- Pesan bot hanya bisa dihapus bila berumur di bawah 48 jam; mitigasi
  off-box adalah forward backup dan unduh berkala ekspor JSON.
- Alert dikirim asinkron (buffered channel 64 + worker) sejak v1.5.0;
  bila channel penuh saat insiden besar, alert bisa tertunda — tidak
  ada outbox persisten (itu T-10, P1).
- Pengiriman alert URGENT saat rantai rusak hanya dibuktikan lewat
  unit test (tidak ada Telegram di instance uji); pengiriman nyata
  diuji saat deploy v1.6.0.

## Pengecualian (T-05)

- Pengecualian adalah pencegahan, bukan bukti serangan yang dicegah:
  pengecekan ledger produksi menunjukkan 0 CREATED di luar simulasi —
  self-DoS belum pernah benar-benar terjadi di produksi.
- Berkas yang dikecualikan tetap masuk baseline tanpa event; bila
  pengecualian dicabut, tidak ada banjir CREATED — tetapi perubahan
  baseline oleh berkas yang dikecualikan membuat verify-baseline
  mismatch sampai rebuild berikutnya (SOP yang sama dengan perubahan
  sah lainnya).

## Angka memori

- Angka "HeapAlloc Go ~2 MB" di naskah lama adalah heap, bukan RSS.
  RSS proses yang sebenarnya ~18–24 MB (terukur, UJ-19); overhead
  PM2/Node ~110 MB terpisah. Semua masih jauh di bawah target
  256 MB — dan sejak v1.6.0 target itu ditegakkan oleh MemoryMax,
  bukan hanya diklaim.

## Skala

- Pengujian skala ~20.000 berkas BELUM dilakukan (bagian dari paket
  bukti v1.6.0, setelah pembekuan).
- Seluruh UJ harus dijalankan ulang pada SATU versi beku v1.6.0;
  angka-angka pra-beku di paket ini adalah bukti ronde pengembangan.
