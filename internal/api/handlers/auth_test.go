package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
)

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ServerPort:   "127.0.0.1:8080",
		JWTSecret:    "test-jwt-secret-for-auth-tests",
		LoginPath:    "/api/v1/secure-gate",
		CookieSecure: false,
		WatchPaths:   []string{"/tmp"},
	}
}

func setupAdmin(t *testing.T, cfg *config.Config, username, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	cfg.Update(func(c *config.Config) {
		c.AdminUsername = username
		c.AdminPassword = string(hash)
	})
}

func doJSON(t *testing.T, h http.HandlerFunc, method, path string, body interface{}, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestSetupPasswordRejectsEmptyUsername(t *testing.T) {
	cfg := newTestConfig(t)
	h := NewAuthHandler(cfg, nil)

	rec := doJSON(t, h.SetupPassword, http.MethodPost, "/api/v1/setup",
		map[string]string{"username": "   ", "password": "password123"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty username, got %d: %s", rec.Code, rec.Body.String())
	}
	if cfg.IsAdminConfigured() {
		t.Fatal("empty username must not configure the admin account")
	}
	// Akun tetap bisa dibuat dengan username yang valid setelahnya.
	rec = doJSON(t, h.SetupPassword, http.MethodPost, "/api/v1/setup",
		map[string]string{"username": "admin", "password": "password123"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid setup, got %d: %s", rec.Code, rec.Body.String())
	}
	if snap := cfg.Snapshot(); snap.AdminUsername != "admin" {
		t.Fatalf("expected admin username 'admin', got %q", snap.AdminUsername)
	}
}

func TestSetupPasswordRejectsTooLongPassword(t *testing.T) {
	cfg := newTestConfig(t)
	h := NewAuthHandler(cfg, nil)

	// Bcrypt menolak password >72 byte; handler harus membalas 400 yang
	// jelas, bukan 500 "failed to hash password".
	rec := doJSON(t, h.SetupPassword, http.MethodPost, "/api/v1/setup",
		map[string]string{"username": "admin", "password": strings.Repeat("x", 73)}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 73-byte password, got %d: %s", rec.Code, rec.Body.String())
	}
	if cfg.IsAdminConfigured() {
		t.Fatal("overlong password must not configure the admin account")
	}
	// Batas tepat 72 byte masih diterima.
	rec = doJSON(t, h.SetupPassword, http.MethodPost, "/api/v1/setup",
		map[string]string{"username": "admin", "password": strings.Repeat("x", 72)}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for 72-byte password, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSetupAuditorRejectsTooLongPassword(t *testing.T) {
	cfg := newTestConfig(t)
	setupAdmin(t, cfg, "admin", "password123")
	h := NewAuthHandler(cfg, nil)

	// SetupAuditor butuh sesi Super Admin di router; di level handler ini
	// yang diuji hanya validasinya (router sudah memastikan role).
	rec := doJSON(t, h.SetupAuditor, http.MethodPost, "/api/v1/setup/auditor",
		map[string]string{"username": "auditor", "password": strings.Repeat("x", 100)}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 100-byte auditor password, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogoutRevokesToken(t *testing.T) {
	cfg := newTestConfig(t)
	setupAdmin(t, cfg, "admin", "password123")
	l, err := ledger.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	h := NewAuthHandler(cfg, l)

	loginRec := doJSON(t, h.Login, http.MethodPost, "/api/v1/secure-gate",
		map[string]string{"username": "admin", "password": "password123"}, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", loginRec.Code, loginRec.Body.String())
	}
	var cookies []*http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == middleware.SessionCookieName {
			cookies = append(cookies, c)
		}
	}
	if len(cookies) == 0 {
		t.Fatal("login must set the session cookie")
	}

	// Sesi valid sebelum logout.
	meRec := doJSON(t, h.Me, http.MethodGet, "/api/v1/auth/me", nil, cookies)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me before logout must be 200, got %d", meRec.Code)
	}

	logoutRec := doJSON(t, h.Logout, http.MethodPost, "/api/v1/auth/logout", nil, cookies)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout must be 200, got %d: %s", logoutRec.Code, logoutRec.Body.String())
	}

	// Token yang sama harus ditolak setelah logout (jti di denylist).
	meRec = doJSON(t, h.Me, http.MethodGet, "/api/v1/auth/me", nil, cookies)
	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout must be 401, got %d", meRec.Code)
	}
}
