package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/scanner"
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

	// Direktori symlink di dalam root yang mengarah ke luar harus ditolak.
	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(insideDir, "link")
	if err := os.Symlink(outsideDir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if isPathWithinRoots([]string{root}, filepath.Join(link, "secret.txt")) {
		t.Fatal("expected path through a symlink escaping the root to be rejected")
	}
	// Symlink yang tetap di dalam root tetap diizinkan.
	innerTarget := filepath.Join(insideDir, "real.txt")
	if err := os.WriteFile(innerTarget, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	innerLink := filepath.Join(insideDir, "inner-link.txt")
	if err := os.Symlink(innerTarget, innerLink); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if !isPathWithinRoots([]string{root}, innerLink) {
		t.Fatal("expected symlink staying inside the root to be allowed")
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
		"http://100.64.0.1/hook",
		"http://192.0.0.170/hook",
		"http://198.18.0.1/hook",
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

func TestScanAndSaveBaselineRecordsModes(t *testing.T) {
	// Regresi T-06: rebuild baseline HARUS mencatat mode tiap berkas.
	// Sebelum perbaikan, scanAndSaveBaseline menulis Mode 0 untuk semua
	// berkas; siklus berikutnya mengadopsi mode diam-diam sehingga digest
	// baseline berubah tepat setelah rebuild dan verify-baseline selalu
	// mismatch sampai rebuild berikutnya.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.php"), []byte("<?php // a"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.php"), []byte("<?php // b"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	l, err := ledger.New(filepath.Join(t.TempDir(), "baseline.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	defer l.Close()

	sc := scanner.New(2, []string{root})
	total, err := scanAndSaveBaseline(sc, l)
	if err != nil {
		t.Fatalf("scanAndSaveBaseline: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	baseline, err := l.GetBaseline()
	if err != nil {
		t.Fatalf("GetBaseline: %v", err)
	}
	if baseline[filepath.Join(root, "a.php")].Mode != 0o644 {
		t.Fatalf("a.php mode = %04o, want 0644", baseline[filepath.Join(root, "a.php")].Mode)
	}
	if baseline[filepath.Join(root, "b.php")].Mode != 0o600 {
		t.Fatalf("b.php mode = %04o, want 0600", baseline[filepath.Join(root, "b.php")].Mode)
	}
	// Digest baseline harus stabil melewati satu siklus perbandingan
	// (tidak ada adopsi mode yang mengubahnya).
	digest1, count1, err := l.BaselineDigest()
	if err != nil {
		t.Fatalf("BaselineDigest: %v", err)
	}
	results, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	res := scanner.CompareWithBaseline(results, baseline, 2, nil)
	if len(res.ModeAdoptions) != 0 {
		t.Fatalf("fresh rebuild must not need mode adoption, got %v", res.ModeAdoptions)
	}
	if err := l.AdoptBaselineModes(res.ModeAdoptions); err != nil {
		t.Fatalf("AdoptBaselineModes: %v", err)
	}
	digest2, count2, err := l.BaselineDigest()
	if err != nil {
		t.Fatalf("BaselineDigest: %v", err)
	}
	if digest1 != digest2 || count1 != count2 {
		t.Fatalf("digest changed after one cycle: %s/%d -> %s/%d", digest1, count1, digest2, count2)
	}
	// Dan VerifyBaselineDigest pada blok baseline yang baru dicatat harus
	// cocok.
	if _, err := l.AppendBlock(models.AnomalyEvent{FilePath: "[admin]", Action: models.ActionBaselineInit, Actor: "test", Detail: "test", BaselineDigest: digest1, BaselineCount: count1}); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}
	vb, err := l.VerifyBaselineDigest()
	if err != nil {
		t.Fatalf("VerifyBaselineDigest: %v", err)
	}
	if !vb.Match {
		t.Fatalf("VerifyBaselineDigest = %+v, want match", vb)
	}
}
