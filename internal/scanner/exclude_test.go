package scanner

import (
	"testing"

	"github.com/skripsi/fim-ipl/internal/models"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"wp-content/cache/**", "wp-content/cache/x.php", true},
		{"wp-content/cache/**", "wp-content/cache/a/b/c.php", true},
		{"wp-content/cache/**", "wp-content/cache", true}, // "**" cocok dengan nol segmen
		{"wp-content/cache/**", "wp-content/uploads/x.jpg", false},
		{"wp-content/cache/*", "wp-content/cache/x.php", true},
		{"wp-content/cache/*", "wp-content/cache/a/b.php", false}, // "*" tidak menembus "/"
		{"wp-content/*/temp/**", "wp-content/cache/temp/a.php", true},
		{"wp-content/*/temp/**", "wp-content/cache/other/a.php", false},
		{"**", "apa/saja.php", true},
		{"*.php", "index.php", true},
		{"*.php", "sub/index.php", false},
		{"wp-content/uploads/*.jpg", "wp-content/uploads/foto.jpg", true},
		{"/var/www/html/wp-content/cache/**", "/var/www/html/wp-content/cache/x.php", true},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.name); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestValidateGlobs(t *testing.T) {
	if err := ValidateGlobs([]string{"wp-content/cache/**", "wp-content/upgrade/**"}); err != nil {
		t.Fatalf("valid globs rejected: %v", err)
	}
	if err := ValidateGlobs([]string{"wp-content/[abc"}); err == nil {
		t.Fatal("malformed glob must be rejected")
	}
	if err := ValidateGlobs([]string{""}); err == nil {
		t.Fatal("empty glob must be rejected")
	}
}

func TestExclusionsUploadsPolicy(t *testing.T) {
	ex := &Exclusions{
		Globs:      []string{"wp-content/cache/**", "wp-content/upgrade/**"},
		WatchPaths: []string{"/var/www/html"},
	}
	cases := []struct {
		path string
		want bool
	}{
		// Kebijakan uploads: non-kode dikecualikan.
		{"/var/www/html/wp-content/uploads/2026/11/foto.jpg", true},
		{"/var/www/html/wp-content/uploads/dokumen.pdf", true},
		{"/var/www/html/wp-content/uploads/video.mp4", true},
		// ...tetapi berkas yang menyerupai kode TETAP dipantau.
		{"/var/www/html/wp-content/uploads/shell.php", false},
		{"/var/www/html/wp-content/uploads/shell.php.jpg", false},
		{"/var/www/html/wp-content/uploads/.htaccess", false},
		{"/var/www/html/wp-content/uploads/shell.phtml", false},
		// Glob konfigurasi.
		{"/var/www/html/wp-content/cache/w3tc/page.html", true},
		{"/var/www/html/wp-content/upgrade/plugin.zip", true},
		{"/var/www/html/wp-content/cache/shell.php", true}, // glob mengecualikan apa pun — pilihan eksplisit admin
		// Di luar pengecualian.
		{"/var/www/html/wp-config.php", false},
		{"/var/www/html/wp-content/plugins/baik/plugin.php", false},
		{"/var/www/html/wp-content/uploads.php", false}, // bukan direktori uploads
		// Di luar watch root.
		{"/etc/passwd", false},
	}
	for _, tc := range cases {
		if got := ex.IsExcluded(tc.path); got != tc.want {
			t.Errorf("IsExcluded(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	// Nil = tidak ada pengecualian (tetapi kebijakan uploads tidak bisa
	// dimatikan lewat nil — nil berarti "tidak ada aturan sama sekali",
	// dipakai test lama yang tidak mengenal T-05).
	if (&Exclusions{}).IsExcluded("/var/www/html/wp-content/uploads/foto.jpg") {
		t.Error("empty Exclusions with no WatchPaths must not exclude anything")
	}
	if (*Exclusions)(nil).IsExcluded("/var/www/html/wp-content/uploads/foto.jpg") {
		t.Error("nil Exclusions must not exclude anything")
	}
}

func TestCompareWithBaselineExclusions(t *testing.T) {
	ex := &Exclusions{
		Globs:      []string{"wp-content/cache/**"},
		WatchPaths: []string{"/var/www/html"},
	}
	baseline := map[string]models.FileRecord{
		"/var/www/html/wp-content/cache/page.html":  {Path: "/var/www/html/wp-content/cache/page.html", Hash: "old", Mode: 0o644},
		"/var/www/html/wp-content/uploads/lama.jpg": {Path: "/var/www/html/wp-content/uploads/lama.jpg", Hash: "old", Mode: 0o644},
		"/var/www/html/index.php":                   {Path: "/var/www/html/index.php", Hash: "same", Mode: 0o644},
		// Entri baseline yang dikecualikan dan sudah tidak ada di disk
		// (dihapus) → bukan DELETED.
		"/var/www/html/wp-content/cache/hilang.html": {Path: "/var/www/html/wp-content/cache/hilang.html", Hash: "gone", Mode: 0o644},
	}
	results := []models.ScanResult{
		// MODIFIED pada berkas cache yang dikecualikan → bukan event.
		{Path: "/var/www/html/wp-content/cache/page.html", Hash: "new", Mode: 0o644, Size: 1},
		// MODIFIED pada gambar uploads yang dikecualikan → bukan event.
		{Path: "/var/www/html/wp-content/uploads/lama.jpg", Hash: "new", Mode: 0o644, Size: 1},
		// Gambar baru di uploads → bukan CREATED, tetapi dihitung.
		sr("/var/www/html/wp-content/uploads/2026/11/baru.jpg", "fresh"),
		// Shell di uploads → TETAP CREATED (kebijakan uploads tidak
		// melindungi berkas yang menyerupai kode).
		sr("/var/www/html/wp-content/uploads/shell.php", "evil"),
		// Berkas biasa tidak berubah (mode harus sama dengan baseline
		// agar tidak terhitung MODE_CHANGED).
		{Path: "/var/www/html/index.php", Hash: "same", Mode: 0o644, Size: 1},
	}

	res := CompareWithBaseline(results, baseline, 2, ex)

	if len(res.Modified) != 0 {
		t.Fatalf("modified on excluded files must not produce events, got %v", res.Modified)
	}
	if len(res.Created) != 1 || res.Created[0].FilePath != "/var/www/html/wp-content/uploads/shell.php" {
		t.Fatalf("expected exactly one CREATED (shell.php), got %v", res.Created)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("deleted excluded files must not produce events, got %v", res.Deleted)
	}
	if res.ExcludedFiles != 4 {
		t.Fatalf("ExcludedFiles = %d, want 4 (cache modified, uploads modified, uploads created, cache deleted)", res.ExcludedFiles)
	}
	if len(res.Excluded) != 4 {
		t.Fatalf("Excluded = %v, want 4 paths", res.Excluded)
	}
	if res.TotalAnomalies() != 1 {
		t.Fatalf("TotalAnomalies = %d, want 1", res.TotalAnomalies())
	}
}

func TestCompareWithBaselineExclusionsAdoptsMode(t *testing.T) {
	// Baseline lama (Mode == 0) pada path yang dikecualikan tetap
	// mengadopsi mode yang teramati — baseline tetap lengkap.
	ex := &Exclusions{
		Globs:      []string{"wp-content/cache/**"},
		WatchPaths: []string{"/var/www/html"},
	}
	baseline := map[string]models.FileRecord{
		"/var/www/html/wp-content/cache/page.html": {Path: "/var/www/html/wp-content/cache/page.html", Hash: "same", Mode: 0},
	}
	results := []models.ScanResult{
		{Path: "/var/www/html/wp-content/cache/page.html", Hash: "same", Mode: 0o644, Size: 1},
	}
	res := CompareWithBaseline(results, baseline, 1, ex)
	if len(res.Modified) != 0 || len(res.ModeChanged) != 0 {
		t.Fatalf("no event expected for excluded path, got modified=%v modeChanged=%v", res.Modified, res.ModeChanged)
	}
	if res.ModeAdoptions["/var/www/html/wp-content/cache/page.html"] != 0o644 {
		t.Fatalf("mode adoption missing for excluded path: %v", res.ModeAdoptions)
	}
	if res.ExcludedFiles != 1 {
		t.Fatalf("ExcludedFiles = %d, want 1", res.ExcludedFiles)
	}
}
