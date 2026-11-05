package fsx

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestChmodNoFollowRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ChmodNoFollow(path, 0o600); err != nil {
		t.Fatalf("ChmodNoFollow: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %04o", info.Mode().Perm())
	}
}

func TestChmodNoFollowRefusesSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rute /proc/self/fd hanya tersedia di Linux")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink tidak tersedia: %v", err)
	}
	// chmod lewat fd pada symlink gagal (EOPNOTSUPP): target tidak pernah
	// tersentuh. Penolakan symlink eksplisit dilakukan Lstat di caller.
	if err := ChmodNoFollow(link, 0o000); err == nil {
		t.Fatal("ChmodNoFollow must refuse a symlink")
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target must keep mode 0644, got %04o", info.Mode().Perm())
	}
}
