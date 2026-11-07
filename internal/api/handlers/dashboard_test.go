package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

func TestGetStatusIncludesLastVerified(t *testing.T) {
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "status.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	h := NewDashboardHandler(l, scanner.New(1, []string{root}))

	// Belum ada verifikasi: field last_verified tidak ada.
	rec := httptest.NewRecorder()
	h.GetStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var status map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := status["last_verified"]; ok {
		t.Fatal("last_verified must be absent before any verification")
	}

	// Setelah verifikasi dicatat: field ada dengan isinya.
	if err := l.RecordVerification(models.LastVerification{
		VerifiedAt:    time.Now().UTC(),
		ChainValid:    true,
		ChainMessage:  "chain intact",
		HeadBlockID:   "BLK-000022",
		HeadHash:      "0123456789abcdef",
		TotalBlocks:   22,
		BaselineMatch: true,
	}); err != nil {
		t.Fatalf("RecordVerification: %v", err)
	}
	rec = httptest.NewRecorder()
	h.GetStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/status", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	lv, ok := status["last_verified"].(map[string]interface{})
	if !ok {
		t.Fatalf("last_verified missing or wrong type: %v", status["last_verified"])
	}
	if lv["head_block_id"] != "BLK-000022" || lv["chain_valid"] != true {
		t.Fatalf("last_verified = %v", lv)
	}
}
