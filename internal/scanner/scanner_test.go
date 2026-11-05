package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skripsi/fim-ipl/internal/models"
)

func TestIsCodeLike(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"shell.php", true},
		{"index.phtml", true},
		{"app.PHP", true},
		{".htaccess", true},
		{".user.ini", true},
		{"config.ini", true},
		{"cron.sh", true},
		{"photo.png", false},
		{"video.mp4", false},
		{"archive.zip", false},
		// Double extension: jangan sampai webshell lolos dari pemindaian.
		{"shell.php.jpg", true},
		{"shell.PHP.JPG", true},
		{"payload.phtml.png", true},
		{"lib.phar.jpg", true},
	}

	for _, tc := range cases {
		if got := isCodeLike(tc.path); got != tc.want {
			t.Fatalf("isCodeLike(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestScanReportsSymlinkWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("outside watch path"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "backdoor.php")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink tidak tersedia di lingkungan ini: %v", err)
	}

	sc := New(2, []string{root})
	results, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var found bool
	for _, res := range results {
		if res.Path != link {
			continue
		}
		found = true
		if res.Err == nil {
			t.Fatal("symlink seharusnya dilaporkan sebagai error")
		}
		if res.Hash != "" {
			t.Fatalf("symlink tidak boleh menghasilkan hash, got %q", res.Hash)
		}
	}
	if !found {
		t.Fatalf("symlink %s tidak dilaporkan; results=%+v", link, results)
	}
}

func TestScanReportsOversizeNonCodeFileAsSkipped(t *testing.T) {
	root := t.TempDir()

	big := filepath.Join(root, "video.mp4")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse file: 51 MB tanpa menulis 51 MB data.
	if err := f.Truncate(51 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	f.Close()

	small := filepath.Join(root, "small.mp4")
	if err := os.WriteFile(small, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := New(2, []string{root})
	results, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var bigResult, smallResult *models.ScanResult
	for i := range results {
		switch results[i].Path {
		case big:
			bigResult = &results[i]
		case small:
			smallResult = &results[i]
		}
	}
	if bigResult == nil {
		t.Fatalf("oversize file not present in scan results: %+v", results)
	}
	if bigResult.Err == nil || !errors.Is(bigResult.Err, ErrFileOversize) {
		t.Fatalf("expected ErrFileOversize for %s, got %v", big, bigResult.Err)
	}
	if bigResult.Hash != "" {
		t.Fatalf("oversize file must not be hashed, got %q", bigResult.Hash)
	}
	if smallResult == nil || smallResult.Err != nil {
		t.Fatalf("small file should be scanned normally, got %+v", smallResult)
	}
}

func TestScanRecordsFileMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.php")
	if err := os.WriteFile(path, []byte("<?php // test"), 0o640); err != nil {
		t.Fatal(err)
	}

	sc := New(2, []string{root})
	results, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %+v", results)
	}
	if results[0].Mode != 0o640 {
		t.Fatalf("expected mode 0640, got %04o", results[0].Mode)
	}
	if results[0].Hash == "" {
		t.Fatal("expected a hash for a readable file")
	}
}

func TestHashFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("O_NOFOLLOW hanya berlaku di Linux")
	}
	// Catatan: pengujian ini berjalan di Linux (VPS/produksi). Di Windows,
	// HashFile memakai open biasa dan penolakan symlink ditangani Lstat
	// di worker/collectFiles.
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "real.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink tidak tersedia di lingkungan ini: %v", err)
	}
	if _, err := HashFile(link); err == nil {
		t.Fatal("HashFile harus menolak symlink (O_NOFOLLOW)")
	}
	// File biasa tetap bisa di-hash.
	if _, err := HashFile(target); err != nil {
		t.Fatalf("HashFile file biasa gagal: %v", err)
	}
}

func TestCollectFilesSymlinkDirNotFollowed(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "hidden.php"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "uploads")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("symlink tidak tersedia di lingkungan ini: %v", err)
	}

	sc := New(2, []string{root})
	results, err := sc.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	for _, res := range results {
		if res.Path == filepath.Join(outside, "hidden.php") {
			t.Fatal("isi direktori symlink tidak boleh dipindai")
		}
	}
}
