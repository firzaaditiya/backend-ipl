package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPPprefersCFConnectingIP(t *testing.T) {
	old := trustProxy
	trustProxy = true
	defer func() { trustProxy = old }()

	// XFF berisi rantai palsu + IP tunnel; CF-Connecting-IP yang ditulis
	// ulang edge Cloudflare harus menang.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.7")
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 203.0.113.7, 127.0.0.1")
	r.RemoteAddr = "127.0.0.1:54321"
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q, want 203.0.113.7", got)
	}
}

func TestClientIPFallsBackToXFFWithoutCFHeader(t *testing.T) {
	old := trustProxy
	trustProxy = true
	defer func() { trustProxy = old }()

	// Tanpa CF-Connecting-IP (akses lokal/langsung), XFF yang sudah
	// ditimpa Nginx dengan $remote_addr dipakai.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "192.0.2.55")
	r.RemoteAddr = "127.0.0.1:54321"
	if got := clientIP(r); got != "192.0.2.55" {
		t.Fatalf("clientIP = %q, want 192.0.2.55", got)
	}
}

func TestClientIPIgnoresHeadersWithoutTrustProxy(t *testing.T) {
	old := trustProxy
	trustProxy = false
	defer func() { trustProxy = old }()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.7")
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	r.RemoteAddr = "127.0.0.1:54321"
	if got := clientIP(r); got != "127.0.0.1" {
		t.Fatalf("clientIP = %q, want 127.0.0.1", got)
	}
}
