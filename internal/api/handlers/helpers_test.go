package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWatchPathsRejectsMissingDir(t *testing.T) {
	if _, err := validateWatchPaths([]string{filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Fatal("expected missing directory to be rejected")
	}
}

func TestValidateWatchPathsRejectsEmpty(t *testing.T) {
	if _, err := validateWatchPaths([]string{"", "  "}); err == nil {
		t.Fatal("expected empty watch path list to be rejected")
	}
}

func TestValidateWatchPathsNormalizesAndDeduplicates(t *testing.T) {
	dir := t.TempDir()

	paths, err := validateWatchPaths([]string{dir, dir, ""})
	if err != nil {
		t.Fatalf("validateWatchPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 deduplicated path, got %d (%v)", len(paths), paths)
	}
	if !filepath.IsAbs(paths[0]) {
		t.Fatalf("expected absolute path, got %s", paths[0])
	}
}

func TestIsPathWithinRoots(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "uploads", "shell.php")
	insideDir := filepath.Join(root, "uploads")

	if err := os.MkdirAll(insideDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(inside, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !isPathWithinRoots([]string{root}, inside) {
		t.Fatal("expected file inside root to be allowed")
	}
	if !isPathWithinRoots([]string{root}, root) {
		t.Fatal("expected root itself to be allowed")
	}

	outside := filepath.Join(filepath.Dir(root), "outside.php")
	if isPathWithinRoots([]string{root}, outside) {
		t.Fatal("expected file outside root to be rejected")
	}
	// Prefix yang mirip (root-evil) tidak boleh lolos.
	if isPathWithinRoots([]string{root}, root+"-evil/x.php") {
		t.Fatal("expected sibling directory with similar prefix to be rejected")
	}
}

func TestValidateWebhookURL(t *testing.T) {
	valid := []string{
		"",
		"https://8.8.8.8/hook",
		"http://93.184.216.34:9000/x",
		"https://[2001:4860:4860::8888]/hook",
	}
	for _, u := range valid {
		if err := validateWebhookURL(u); err != nil {
			t.Fatalf("expected %q valid, got %v", u, err)
		}
	}

	invalid := []string{
		"example.com",
		"ftp://example.com",
		"https://",
		"javascript:alert(1)",
		"http://localhost/hook",
		"http://10.0.0.1:9000/x",
		"http://127.0.0.1/hook",
		"http://192.168.1.10/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://0.0.0.0/hook",
		"http://[::1]/hook",
	}
	for _, u := range invalid {
		if err := validateWebhookURL(u); err == nil {
			t.Fatalf("expected %q invalid (SSRF guard)", u)
		}
	}
}

func TestValidateOrigins(t *testing.T) {
	got, err := validateOrigins([]string{"http://localhost:3000/", " https://app.local "})
	if err != nil {
		t.Fatalf("validateOrigins: %v", err)
	}
	if len(got) != 2 || got[0] != "http://localhost:3000" || got[1] != "https://app.local" {
		t.Fatalf("unexpected origins: %v", got)
	}

	invalid := [][]string{
		{"*"},
		{"http://localhost:3000/path"},
		{"localhost:3000"},
		{"ftp://host"},
	}
	for _, origins := range invalid {
		if _, err := validateOrigins(origins); err == nil {
			t.Fatalf("expected %v to be rejected", origins)
		}
	}
}
