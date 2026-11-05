package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
