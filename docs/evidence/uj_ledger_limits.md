# Uji Batas Ledger (v1.6.0, T-06 / UJ-17)

Pengujian batas ledger hash-chain pada instance uji terpisah
(`/opt/fim-test-v16`, port 8090), 5 November 2026, 23:17–23:23 WIB.
Ledger uji: 25 blok (campuran v1 → v2 → v3), head BLK-000025,
head hash `70d507c9…`.

## 1. Pemotongan ekor (tail truncation)

- Ekspor JSON penuh (25 blok) → `fim-verify` menyatakan **VALID**,
  exit 0, head BLK-000025 (`70d507c9…`).
- Ekspor yang sama dipotong 2 blok terakhir (23 blok) → `fim-verify`
  tetap **VALID** (exit 0), head BLK-000023 (`7a37413c…`).
- **Kesimpulan jujur:** verifikasi lokal TIDAK bisa mendeteksi
  pemotongan ekor — rantai yang terpotong tetap konsisten secara
  internal. Yang mendeteksinya adalah perbandingan dengan jangkar
  eksternal: head hash jangkar (BLK-000025, `70d507c9…`, dikirim lewat
  Telegram dan caption backup) TIDAK SAMA dengan head hash rantai
  yang terpotong (BLK-000023, `7a37413c…`) — pemotongan terdeteksi.
- Inilah batas single-node ledger yang harus ditulis di naskah:
  ledger ini *tamper-evident*, bukan *tamper-proof*; deteksi
  pemotongan bergantung pada jangkar di luar server.

## 2. Perusakan satu blok

- Ekspor dengan hash satu blok diubah → `fim-verify` menyatakan
  **INVALID tepat pada BLK-000011**, exit 1.
- Verifikasi rantai (`GET /ledger/verify`) gagal tepat pada blok
  yang dirusak; blok sebelum dan sesudahnya tetap konsisten.

## 3. Perusakan OldMode / field metadata (v2)

- Unit test: perusakan OldMode / NewMode / QuarantineErr / Actor /
  Detail pada blok v2 gagal tepat di blok itu (field-field ini
  masuk material hash v2; di v1 mereka hanya metadata).
- Pemalsuan dengan `|` (pemisah v1): dua kombinasi field yang
  bertabrakan di v1 menghasilkan hash berbeda di v2 (length-prefix).

## 4. Perusakan baseline (bukan rantai)

- Edit langsung satu entri baseline di Bbolt → `verify-baseline`
  melaporkan `match=false` dengan BlockID yang tepat, sementara
  `VerifyChain` tetap valid. Digest baseline dan rantai adalah dua
  pemeriksaan yang saling melengkapi, bukan satu.
- Manipulasi bucket `quarantine_modes` (0600) tidak mengubah mode
  yang dikembalikan saat release (0644, dari rantai) — bucket itu
  hanya fallback sejak T-04 (UJ-16).

## 5. Jangkar eksternal

- Setiap alert Telegram membawa jangkar: alert per-blok mencantumkan
  hash blok lengkap; batch/bulk mencantumkan ID + hash pendek tiap
  blok dan head hash lengkap; caption backup mencantumkan block
  terakhir + head hash.
- Verifikasi terjadwal (1 menit setelah boot, lalu tiap jam) mencatat
  hasil ke `last_verified`; rantai rusak memicu alert URGENT
  "RANTAI LEDGER RUSAK".
- **Catatan jujur:** di instance uji tidak ada Telegram, jadi
  pengiriman alert URGENT saat rantai rusak hanya dibuktikan lewat
  unit test (alert diantrekan) — pengiriman nyata diuji di produksi
  saat deploy v1.6.0.

## Cara mereproduksi

```bash
# Ekspor ledger instance uji, lalu verifikasi dengan fim-verify.
curl -s -b /tmp/cj-test.txt http://127.0.0.1:8090/api/v1/ledger/export -o /tmp/ledger.json
/opt/fim-test-v16/fim-verify /tmp/ledger.json          # exit 0 = VALID
# Potong 2 blok terakhir, verifikasi lagi (tetap VALID — lihat §1).
python3 -c "import json; d=json.load(open('/tmp/ledger.json')); d['blocks']=d['blocks'][:-2]; json.dump(d, open('/tmp/ledger-trunc.json','w'))"
/opt/fim-test-v16/fim-verify /tmp/ledger-trunc.json    # exit 0 = VALID (batas!)
# Rusak satu blok, verifikasi lagi (INVALID tepat di blok itu).
python3 -c "import json; d=json.load(open('/tmp/ledger.json')); d['blocks'][10]['hash']='0'*64; json.dump(d, open('/tmp/ledger-tamper.json','w'))"
/opt/fim-test-v16/fim-verify /tmp/ledger-tamper.json   # exit 1 = INVALID di BLK-000011
```
