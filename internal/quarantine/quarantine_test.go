package quarantine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestApplyAndReleaseRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "victim.php")
	if err := os.WriteFile(path, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	res := Apply(path)
	if !res.Success || res.Err != nil {
		t.Fatalf("expected quarantine success, got %+v", res)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after apply: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o000 {
		t.Fatalf("expected mode 000, got %o", info.Mode().Perm())
	}

	if err := Release(path); err != nil {
		t.Fatalf("Release: %v", err)
	}
	info, _ = os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("expected mode 0644 after release, got %o", info.Mode().Perm())
	}
}

func TestApplySkipsMissingFile(t *testing.T) {
	res := Apply(filepath.Join(t.TempDir(), "missing.php"))
	if res.Success || res.Err != nil {
		t.Fatalf("expected skip with no error, got %+v", res)
	}
	if res.SkipReason == "" {
		t.Fatal("expected a skip reason for missing file")
	}
}

func TestApplyAndReleaseRejectSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.php")
	if err := os.WriteFile(target, []byte("<?php"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	link := filepath.Join(dir, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	if res := Apply(link); res.Success || res.SkipReason == "" {
		t.Fatalf("expected symlink to be skipped, got %+v", res)
	}
	if err := Release(link); err == nil {
		t.Fatal("expected Release to reject symlink")
	}

	// Target asli tidak boleh ikut berubah.
	info, _ := os.Stat(target)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("expected target untouched at 0644, got %o", info.Mode().Perm())
	}
}
