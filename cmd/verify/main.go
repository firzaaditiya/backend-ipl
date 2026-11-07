// Command fim-verify memeriksa ulang rantai hash ledger dari sebuah file
// ekspor JSON (hasil GET /api/v1/ledger/export atau tombol Backup di
// dasbor), TANPA membuka database. Logika verifikasinya persis sama
// dengan yang dipakai server (ledger.VerifyBlocks) — mencakup formula
// hash v1, v2, dan v3 — sehingga hasil dari ekspor tidak bisa berbeda
// dari verifikasi langsung di server.
//
// Pemakaian:
//
//	fim-verify <export.json>
//
// Kode keluar: 0 = rantai utuh, 1 = rantai rusak / ekspor tidak memuat
// blok, 2 = pemakaian salah atau file tidak bisa dibaca/diparse.
//
// BATAS YANG JUJUR (single-node ledger): verifier ini TIDAK dapat
// mendeteksi pemotongan ekor (tail truncation) — menghapus blok-blok
// terakhir menghasilkan rantai yang lebih pendek tetapi tetap utuh.
// Yang mendeteksinya adalah perbandingan dengan jangkar eksternal:
// head hash di alert Telegram / caption backup (T-06). Bila head hash
// di Telegram tidak sama dengan head hash yang dilaporkan verifier ini,
// ada blok yang hilang.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "pemakaian: %s <export.json>\n", os.Args[0])
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "tidak dapat membaca %s: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	blocks, err := parseExport(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tidak dapat mem-parse %s: %v\n", os.Args[1], err)
		os.Exit(2)
	}
	if len(blocks) == 0 {
		fmt.Fprintln(os.Stderr, "ekspor tidak memuat blok apa pun")
		os.Exit(1)
	}

	res := ledger.VerifyBlocks(blocks)
	if !res.Valid {
		fmt.Printf("INVALID: %s (gagal pada %s)\n", res.Message, res.FailedBlock)
		os.Exit(1)
	}
	fmt.Printf("VALID: %d blok, head %s (%s)\n", res.TotalBlocks, res.HeadBlockID, res.HeadHash)
}

// parseExport menerima dua bentuk ekspor: objek {"blocks": [...]} (format
// GET /api/v1/ledger/export) dan array blok polos [...].
func parseExport(data []byte) ([]models.Block, error) {
	var exp struct {
		Blocks []models.Block `json:"blocks"`
	}
	if err := json.Unmarshal(data, &exp); err == nil && exp.Blocks != nil {
		return exp.Blocks, nil
	}
	var blocks []models.Block
	if err := json.Unmarshal(data, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}
