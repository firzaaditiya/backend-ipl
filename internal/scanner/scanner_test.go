package scanner

import (
	"os"
	"path/filepath"
	"testing"
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
