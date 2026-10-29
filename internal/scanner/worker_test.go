package scanner

import (
	"os"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
)

func sr(path, hash string) models.ScanResult {
	return models.ScanResult{Path: path, Hash: hash, Size: 1, ModTime: time.Now()}
}

func TestCompareWithBaselineDetectsAllActions(t *testing.T) {
	baseline := map[string]models.FileRecord{
		"/w/unchanged.php": {Path: "/w/unchanged.php", Hash: "same"},
		"/w/modified.php":  {Path: "/w/modified.php", Hash: "old"},
		"/w/deleted.php":   {Path: "/w/deleted.php", Hash: "gone"},
	}

	results := []models.ScanResult{
		sr("/w/unchanged.php", "same"),
		sr("/w/modified.php", "new"),
		sr("/w/created.php", "fresh"),
	}

	res := CompareWithBaseline(results, baseline)

	if len(res.Modified) != 1 || res.Modified[0].FilePath != "/w/modified.php" {
		t.Fatalf("expected 1 modified file, got %+v", res.Modified)
	}
	if len(res.Created) != 1 || res.Created[0].FilePath != "/w/created.php" {
		t.Fatalf("expected 1 created file, got %+v", res.Created)
	}
	if len(res.Deleted) != 1 || res.Deleted[0].FilePath != "/w/deleted.php" {
		t.Fatalf("expected 1 deleted file, got %+v", res.Deleted)
	}
	if res.TotalAnomalies() != 3 {
		t.Fatalf("expected 3 anomalies, got %d", res.TotalAnomalies())
	}
}

func TestCompareWithBaselineIgnoresMtimeOnlyChange(t *testing.T) {
	baseline := map[string]models.FileRecord{
		"/w/a.php": {Path: "/w/a.php", Hash: "hash", ModTime: time.Now().Add(-time.Hour)},
	}
	// Hash sama, mtime berbeda â†’ bukan anomali (anti touch() spoof).
	result := sr("/w/a.php", "hash")
	result.ModTime = time.Now()

	res := CompareWithBaseline([]models.ScanResult{result}, baseline)
	if res.TotalAnomalies() != 0 {
		t.Fatalf("expected no anomalies for hash-equal file, got %d", res.TotalAnomalies())
	}
}

func TestCompareWithBaselineIsDeterministic(t *testing.T) {
	baseline := map[string]models.FileRecord{}

	results := []models.ScanResult{
		sr("/w/z.php", "1"),
		sr("/w/a.php", "1"),
		sr("/w/m.php", "1"),
	}

	res := CompareWithBaseline(results, baseline)
	if len(res.Created) != 3 {
		t.Fatalf("expected 3 created, got %d", len(res.Created))
	}
	order := []string{res.Created[0].FilePath, res.Created[1].FilePath, res.Created[2].FilePath}
	want := []string{"/w/a.php", "/w/m.php", "/w/z.php"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("expected sorted order %v, got %v", want, order)
		}
	}
}

func TestCompareUnreadableIsNotDeleted(t *testing.T) {
	baseline := map[string]models.FileRecord{
		"/w/secret.php": {Path: "/w/secret.php", Hash: "known"},
	}
	results := []models.ScanResult{
		{Path: "/w/secret.php", Err: os.ErrPermission},
	}

	res := CompareWithBaseline(results, baseline)

	if len(res.Deleted) != 0 {
		t.Fatalf("file tidak terbaca tidak boleh dianggap DELETED: %+v", res.Deleted)
	}
	if len(res.Unreadable) != 1 {
		t.Fatalf("expected 1 unreadable, got %+v", res.Unreadable)
	}
	got := res.Unreadable[0]
	if got.Action != models.ActionUnreadable || got.OldHash != "known" || got.ScanErr == "" {
		t.Fatalf("unexpected unreadable event: %+v", got)
	}
}

func TestCompareUnreadableNewFileIsReported(t *testing.T) {
	results := []models.ScanResult{
		{Path: "/w/backdoor.php", Err: os.ErrPermission},
	}

	res := CompareWithBaseline(results, map[string]models.FileRecord{})

	if len(res.Created) != 0 || len(res.Deleted) != 0 {
		t.Fatalf("unreadable baru tidak boleh menjadi CREATED/DELETED: %+v", res)
	}
	if len(res.Unreadable) != 1 || res.Unreadable[0].FilePath != "/w/backdoor.php" {
		t.Fatalf("unreadable baru tidak dilaporkan: %+v", res.Unreadable)
	}
	if res.TotalAnomalies() != 1 {
		t.Fatalf("expected 1 anomaly, got %d", res.TotalAnomalies())
	}
}
