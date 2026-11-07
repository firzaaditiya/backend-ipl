package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/backup"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/notifier"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

func TestOriginAllowed(t *testing.T) {
	allowed := []string{"http://localhost:3000/", "https://app.example.com"}

	if !originAllowed(allowed, "http://localhost:3000") {
		t.Fatal("expected trailing-slash origin to match")
	}
	if !originAllowed(allowed, "https://APP.example.com") {
		t.Fatal("expected case-insensitive host to match")
	}
	if originAllowed(allowed, "http://evil.example.com") {
		t.Fatal("expected unknown origin to be rejected")
	}
	if originAllowed(allowed, "http://localhost:3001") {
		t.Fatal("expected different port to be rejected")
	}
}

func requestWithOrigin(method, host, origin string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+"/api/v1/settings", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestCsrfOriginRejected(t *testing.T) {
	allowed := []string{"https://fim.tpqalfawwaz.web.id"}

	// Tanpa Origin (curl/alat admin): lolos.
	if csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", ""), allowed) {
		t.Fatal("expected empty Origin to be allowed")
	}
	// Same-origin lewat proxy: lolos.
	if csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", "https://fim.tpqalfawwaz.web.id"), allowed) {
		t.Fatal("expected same-origin to be allowed")
	}
	// Origin terdaftar: lolos.
	if csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", "https://fim.tpqalfawwaz.web.id"), allowed) {
		t.Fatal("expected allowlisted origin to be allowed")
	}
	// Origin asing: ditolak.
	if !csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", "https://evil.example.com"), allowed) {
		t.Fatal("expected foreign origin to be rejected")
	}
	// Allowlist kosong + Origin asing: ditolak (fail-closed, v1.4.0).
	if !csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", "https://evil.example.com"), nil) {
		t.Fatal("expected foreign origin to be rejected when allowlist is empty")
	}
	// Allowlist kosong + same-origin: tetap lolos.
	if csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", "https://fim.tpqalfawwaz.web.id"), nil) {
		t.Fatal("expected same-origin to be allowed when allowlist is empty")
	}
	// Origin tidak valid: ditolak.
	if !csrfOriginRejected(requestWithOrigin("POST", "fim.tpqalfawwaz.web.id", "://bad"), allowed) {
		t.Fatal("expected malformed origin to be rejected")
	}
}

func testRouter(t *testing.T) (http.Handler, *ledger.Ledger) {
	t.Helper()
	root := t.TempDir()
	l, err := ledger.New(filepath.Join(root, "router.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	cfg := &config.Config{
		JWTSecret:       "test-jwt-secret-yang-cukup-panjang-untuk-test",
		SessionEpoch:    0,
		AdminUsername:   "admin",
		WatchPaths:      []string{root},
		ScanIntervalSec: 30,
		WorkerCount:     2,
		LoginPath:       "/api/v1/secure-gate",
	}
	sc := scanner.New(2, []string{root})
	tg := notifier.NewTelegram("", "")
	bm := backup.NewManager(l, tg, "", 24*time.Hour)
	hub := realtime.NewHub()
	t.Cleanup(func() { hub.Close() })

	return NewRouter(cfg, l, sc, tg, bm, hub), l
}

func tokenFor(t *testing.T, username, role string) string {
	t.Helper()
	token, _, err := middleware.GenerateToken(username, role, "test-jwt-secret-yang-cukup-panjang-untuk-test", 24, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return token
}

func TestAuditorMutationEmitsNoBlock(t *testing.T) {
	router, l := testRouter(t)

	r := httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/monitoring/start", nil)
	r.AddCookie(&http.Cookie{Name: "fim_session", Value: tokenFor(t, "auditor1", middleware.RoleAuditor)})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for auditor mutation, got %d: %s", rec.Code, rec.Body.String())
	}
	count, err := l.GetBlockCount()
	if err != nil {
		t.Fatalf("GetBlockCount: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected auditor mutation must not add a block, got %d blocks", count)
	}
}

func TestAdminMutationIsAuditedEndToEnd(t *testing.T) {
	router, l := testRouter(t)

	r := httptest.NewRequest(http.MethodPost, "http://example.com/api/v1/maintenance/enable", nil)
	r.AddCookie(&http.Cookie{Name: "fim_session", Value: tokenFor(t, "admin", middleware.RoleSuperAdmin)})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	blocks, total, err := l.GetBlocks(0, 1)
	if err != nil {
		t.Fatalf("GetBlocks: %v", err)
	}
	if total != 1 || len(blocks) != 1 {
		t.Fatalf("expected exactly 1 block, got total=%d blocks=%d", total, len(blocks))
	}
	b := blocks[0]
	if b.Action != models.ActionMaintenanceOn {
		t.Fatalf("action = %q, want MAINTENANCE_ON", b.Action)
	}
	if b.Actor != "admin (Super Admin) dari 192.0.2.1" {
		t.Fatalf("actor = %q", b.Actor)
	}
	if b.FilePath != models.AdminBlockPath {
		t.Fatalf("file_path = %q, want %q", b.FilePath, models.AdminBlockPath)
	}
	if res := l.VerifyChain(); !res.Valid {
		t.Fatalf("chain invalid: %s", res.Message)
	}
}
