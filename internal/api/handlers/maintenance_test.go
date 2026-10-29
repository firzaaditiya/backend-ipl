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

	anomalies, err := l.GetAnomalyCount()
	if err != nil {
		t.Fatalf("GetAnomalyCount: %v", err)
	}
	if anomalies != 1 {
		t.Fatalf("release must not inflate anomaly count, got %d", anomalies)
	}

	if q, _ := l.IsCurrentlyQuarantined(path); q {
		t.Fatal("expected file to be released")
	}
	if res := l.VerifyChain(); !res.Valid {
		t.Fatalf("chain invalid after release record: %s", res.Message)
	}
}
