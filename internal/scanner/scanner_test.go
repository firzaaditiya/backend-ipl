package scanner

import (
	"errors"
	"os"
	"path/filepath"
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
