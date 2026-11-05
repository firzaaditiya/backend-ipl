package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/quarantine"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

func TestQuarantineReleaseIsAudited(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "shell.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if res := quarantine.Apply(path); !res.Success {
		t.Fatalf("quarantine apply failed: err=%v skip=%s", res.Err, res.SkipReason)
	}

	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	if _, err := l.AppendBlock(models.AnomalyEvent{
		FilePath:    path,
		Action:      models.ActionCreated,
		NewHash:     "deadbeef",
		Quarantined: true,
	}); err != nil {
		t.Fatalf("append anomaly: %v", err)
	}

	hub := realtime.NewHub()
	defer hub.Close()

	h := NewQuarantineHandler(&config.Config{WatchPaths: []string{root}}, l, hub)
	body, _ := json.Marshal(map[string]string{"file_path": path})
	rec := httptest.NewRecorder()
	h.Release(rec, httptest.NewRequest(http.MethodPost, "/api/v1/quarantine/release", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	blocks, err := l.GetBlockCount()
	if err != nil {
		t.Fatalf("GetBlockCount: %v", err)
	}
	if blocks != 2 {
		t.Fatalf("expected an audit block for the release, got %d blocks", blocks)
	}

	counts, err := l.GetDashboardCounts()
	if err != nil {
		t.Fatalf("GetDashboardCounts: %v", err)
	}
	if counts.Anomalies != 1 {
		t.Fatalf("release must not inflate anomaly count, got %d", counts.Anomalies)
	}

	if q, _ := l.IsCurrentlyQuarantined(path); q {
		t.Fatal("expected file to be released")
	}
	if res := l.VerifyChain(); !res.Valid {
		t.Fatalf("chain invalid after release record: %s", res.Message)
	}
}

func TestUpdateBaselineRefusesQuarantinedFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "shell.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	l, err := ledger.New(filepath.Join(t.TempDir(), "baseline.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	// File terkarantina (blok CREATED dengan Quarantined=true).
	if _, err := l.AppendBlock(models.AnomalyEvent{
		FilePath:    path,
		Action:      models.ActionCreated,
		NewHash:     "abc",
		Quarantined: true,
	}); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}

	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewMaintenanceHandler(sc, l, hub)

	rec := httptest.NewRecorder()
	h.UpdateBaseline(rec, httptest.NewRequest(http.MethodPost, "/api/v1/baseline/update", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 while files are quarantined, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response must be JSON: %v", err)
	}
	files, ok := body["quarantined_files"].([]interface{})
	if !ok || len(files) != 1 {
		t.Fatalf("expected quarantined_files list with 1 entry, got %+v", body)
	}
}

func TestUpdateBaselineSucceedsWithoutQuarantine(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php // ok"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	l, err := ledger.New(filepath.Join(t.TempDir(), "baseline2.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewMaintenanceHandler(sc, l, hub)

	rec := httptest.NewRecorder()
	h.UpdateBaseline(rec, httptest.NewRequest(http.MethodPost, "/api/v1/baseline/update", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	count, err := l.GetBaselineCount()
	if err != nil {
		t.Fatalf("GetBaselineCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected baseline with 1 file, got %d", count)
	}
}
