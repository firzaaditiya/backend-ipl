package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/notifier"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

func testAdminConfig(root string) *config.Config {
	return &config.Config{
		JWTSecret:       "test-jwt-secret-yang-cukup-panjang-untuk-test",
		SessionEpoch:    0,
		AdminUsername:   "admin",
		WatchPaths:      []string{root},
		ScanIntervalSec: 30,
		WorkerCount:     2,
		LoginPath:       "/api/v1/secure-gate",
	}
}

func adminRequest(t *testing.T, cfg *config.Config, method, path string, body io.Reader) *http.Request {
	t.Helper()
	token, _, err := middleware.GenerateToken("admin", middleware.RoleSuperAdmin, cfg.JWTSecret, 24, cfg.SessionEpoch)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	r := httptest.NewRequest(method, path, body)
	r.AddCookie(&http.Cookie{Name: "fim_session", Value: token})
	return r
}

func newestBlock(t *testing.T, l *ledger.Ledger) models.Block {
	t.Helper()
	blocks, _, err := l.GetBlocks(0, 1)
	if err != nil {
		t.Fatalf("GetBlocks: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	return blocks[0]
}

func assertAuditBlock(t *testing.T, l *ledger.Ledger, wantAction, wantActor, wantDetail string) {
	t.Helper()
	b := newestBlock(t, l)
	if b.Action != wantAction {
		t.Fatalf("action = %q, want %q", b.Action, wantAction)
	}
	if b.Actor != wantActor {
		t.Fatalf("actor = %q, want %q", b.Actor, wantActor)
	}
	if b.Detail != wantDetail {
		t.Fatalf("detail = %q, want %q", b.Detail, wantDetail)
	}
	if b.FilePath != models.AdminBlockPath {
		t.Fatalf("file_path = %q, want %q", b.FilePath, models.AdminBlockPath)
	}
	if b.HashVersion != 3 {
		t.Fatalf("hash_version = %d, want 3", b.HashVersion)
	}
	if res := l.VerifyChain(); !res.Valid {
		t.Fatalf("chain invalid after audit block: %s", res.Message)
	}
}

const wantAdminActor = "admin (Super Admin) dari 192.0.2.1"

func TestAdminActionMonitoringStartStop(t *testing.T) {
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()
	if err := l.SaveBaseline([]models.FileRecord{
		{Path: filepath.Join(root, "a.php"), Hash: "aaa", Size: 10, ModTime: time.Now(), ScannedAt: time.Now()},
	}); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewSettingsHandler(cfg, l, sc, notifier.NewTelegram("", ""), nil, hub)

	rec := httptest.NewRecorder()
	h.StartMonitoring(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/monitoring/start", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionMonitoringStart, wantAdminActor, "interval 30 detik, 2 worker")
	t.Cleanup(func() { sc.StopMonitoring() })

	rec = httptest.NewRecorder()
	h.StopMonitoring(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/monitoring/stop", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionMonitoringStop, wantAdminActor, "")

	counts, err := l.GetDashboardCounts()
	if err != nil {
		t.Fatalf("GetDashboardCounts: %v", err)
	}
	if counts.Anomalies != 0 {
		t.Fatalf("admin actions must not count as anomalies, got %d", counts.Anomalies)
	}
	if counts.TotalBlocks != 2 {
		t.Fatalf("expected 2 blocks, got %d", counts.TotalBlocks)
	}
}

func TestAdminActionMaintenanceToggle(t *testing.T) {
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewMaintenanceHandler(cfg, sc, l, hub)

	rec := httptest.NewRecorder()
	h.Enable(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/maintenance/enable", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionMaintenanceOn, wantAdminActor, "")

	rec = httptest.NewRecorder()
	h.Disable(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/maintenance/disable", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionMaintenanceOff, wantAdminActor, "")
}

func TestAdminActionSettingsChangedListsFieldNamesOnly(t *testing.T) {
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewSettingsHandler(cfg, l, sc, notifier.NewTelegram("", ""), nil, hub)

	body, _ := json.Marshal(map[string]interface{}{
		"scan_interval_sec": 300,
		"telegram_token":    "SECRET-TOKEN-123",
	})
	rec := httptest.NewRecorder()
	h.UpdateSettings(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/settings", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionSettingsChanged, wantAdminActor, "scan_interval_sec, telegram_token")
	b := newestBlock(t, l)
	if strings.Contains(b.Detail, "SECRET-TOKEN-123") {
		t.Fatalf("detail must never contain secret values: %q", b.Detail)
	}
}

func TestAdminActionBaselineInit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php // ok"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewSettingsHandler(cfg, l, sc, notifier.NewTelegram("", ""), nil, hub)

	rec := httptest.NewRecorder()
	h.InitializeBaseline(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/baseline/init", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionBaselineInit, wantAdminActor, "baseline dibuat: 1 berkas")
}

func TestAdminActionAuditorSet(t *testing.T) {
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	cfg := testAdminConfig(root)
	h := NewAuthHandler(cfg, l)

	body, _ := json.Marshal(map[string]string{"username": "auditor1", "password": "password-yang-kuat-1"})
	rec := httptest.NewRecorder()
	h.SetupAuditor(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/setup/auditor", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionAuditorSet, wantAdminActor, "auditor: auditor1")
}

func TestReleaseRequiresReason(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "shell.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()
	if _, err := l.AppendBlock(models.AnomalyEvent{
		FilePath: path, Action: models.ActionCreated, NewHash: "abc", Quarantined: true,
	}); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	h := NewQuarantineHandler(cfg, l, hub)

	body, _ := json.Marshal(map[string]string{"file_path": path})
	rec := httptest.NewRecorder()
	h.Release(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/quarantine/release", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without reason, got %d: %s", rec.Code, rec.Body.String())
	}
	count, err := l.GetBlockCount()
	if err != nil {
		t.Fatalf("GetBlockCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("rejected release must not add a block, got %d blocks", count)
	}
	if q, _ := l.IsCurrentlyQuarantined(path); !q {
		t.Fatal("file must stay quarantined after a rejected release")
	}
}

func TestUpdateBaselineRequiresReason(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php // ok"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewMaintenanceHandler(cfg, sc, l, hub)

	rec := httptest.NewRecorder()
	h.UpdateBaseline(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/baseline/update", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without reason, got %d: %s", rec.Code, rec.Body.String())
	}
	count, err := l.GetBlockCount()
	if err != nil {
		t.Fatalf("GetBlockCount: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected rebuild must not add a block, got %d blocks", count)
	}
}

func TestUpdateSettingsExcludeGlobs(t *testing.T) {
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	cfg := testAdminConfig(root)
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(2, []string{root})
	h := NewSettingsHandler(cfg, l, sc, notifier.NewTelegram("", ""), nil, hub)

	// Pola valid: tersimpan, tercatat sebagai "exclude_globs" (hanya nama
	// field), dan langsung dipakai scanner.
	body, _ := json.Marshal(map[string]interface{}{
		"exclude_globs": []string{"wp-content/cache/**", "custom/tmp/**"},
	})
	rec := httptest.NewRecorder()
	h.UpdateSettings(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/settings", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertAuditBlock(t, l, models.ActionSettingsChanged, wantAdminActor, "exclude_globs")
	if got := cfg.GetExcludeGlobs(); len(got) != 2 || got[0] != "wp-content/cache/**" {
		t.Fatalf("config globs = %v", got)
	}
	if !sc.Exclusions().IsExcluded(filepath.Join(root, "wp-content/cache/x.html")) {
		t.Fatal("scanner must apply the new globs immediately")
	}

	// Pola tidak valid: ditolak 400, config tidak berubah, tidak ada blok baru.
	body, _ = json.Marshal(map[string]interface{}{
		"exclude_globs": []string{"wp-content/[abc"},
	})
	rec = httptest.NewRecorder()
	h.UpdateSettings(rec, adminRequest(t, cfg, http.MethodPost, "/api/v1/settings", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := cfg.GetExcludeGlobs(); len(got) != 2 {
		t.Fatalf("config globs changed after rejected update: %v", got)
	}
	blocks, _, err := l.GetBlocks(0, 100)
	if err != nil {
		t.Fatalf("GetBlocks: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block (no block for the rejected update), got %d", len(blocks))
	}
}

func TestUpdateSettingsRejectsEnvSourcedTelegram(t *testing.T) {
	// T-07: bila token/chat ID Telegram berasal dari environment, Settings
	// API menolak perubahan atasnya (400) — tetapi perubahan field lain
	// tetap diizinkan.
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(t.TempDir(), "settings-env.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	t.Setenv("FIM_TELEGRAM_TOKEN", "env-token")
	t.Setenv("FIM_TELEGRAM_CHAT_ID", "123456")
	cfg := testAdminConfig(root)
	cfg.ApplyEnvOverrides()
	sc := scanner.New(1, []string{root})
	h := NewSettingsHandler(cfg, l, sc, notifier.NewTelegram("", ""), nil, nil)

	// Mengubah token -> 400, dan tidak ada blok SETTINGS_CHANGED.
	rec := httptest.NewRecorder()
	req := adminRequest(t, cfg, http.MethodPost, "/api/v1/settings", strings.NewReader(`{"telegram_token":"token-baru"}`))
	h.UpdateSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for env-sourced telegram_token, got %d: %s", rec.Code, rec.Body.String())
	}
	// Mengubah chat ID -> 400.
	rec = httptest.NewRecorder()
	req = adminRequest(t, cfg, http.MethodPost, "/api/v1/settings", strings.NewReader(`{"telegram_chat_id":"999"}`))
	h.UpdateSettings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for env-sourced telegram_chat_id, got %d: %s", rec.Code, rec.Body.String())
	}
	// Mengubah interval (bukan Telegram) -> 200.
	rec = httptest.NewRecorder()
	req = adminRequest(t, cfg, http.MethodPost, "/api/v1/settings", strings.NewReader(`{"scan_interval_sec":300}`))
	h.UpdateSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a non-Telegram change, got %d: %s", rec.Code, rec.Body.String())
	}
	// GetSettings menandai sumber env.
	rec = httptest.NewRecorder()
	h.GetSettings(rec, adminRequest(t, cfg, http.MethodGet, "/api/v1/settings", nil))
	var settings map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &settings); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if settings["telegram_token_from_env"] != true || settings["telegram_chat_id_from_env"] != true {
		t.Fatalf("GetSettings must mark Telegram fields as env-sourced: %v", settings)
	}
}
