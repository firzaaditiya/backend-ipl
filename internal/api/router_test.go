package api

import "testing"

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
