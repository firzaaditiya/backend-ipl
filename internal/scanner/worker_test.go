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

	res := CompareWithBaseline(results, baseline, 4, nil)

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

	res := CompareWithBaseline([]models.ScanResult{result}, baseline, 4, nil)
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

	res := CompareWithBaseline(results, baseline, 4, nil)
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

	res := CompareWithBaseline(results, baseline, 4, nil)

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

	res := CompareWithBaseline(results, map[string]models.FileRecord{}, 4, nil)

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

func TestCompareOversizeFileIsNeitherDeletedNorUnreadable(t *testing.T) {
	// File baseline yang tumbuh melewati 50 MB tidak boleh dilaporkan
	// DELETED (file-nya masih ada) maupun UNREADABLE (bukan gagal baca).
	baseline := map[string]models.FileRecord{
		"/w/big.mp4": {Path: "/w/big.mp4", Hash: "oldhash"},
	}
	results := []models.ScanResult{
		{Path: "/w/big.mp4", Err: ErrFileOversize},
	}

	res := CompareWithBaseline(results, baseline, 2, nil)

	if res.TotalAnomalies() != 0 {
		t.Fatalf("expected 0 anomalies for oversize file, got %+v", res)
	}
}

func TestCompareOversizeNewFileIsNotReported(t *testing.T) {
	results := []models.ScanResult{
		{Path: "/w/new-big.mp4", Err: ErrFileOversize},
	}

	res := CompareWithBaseline(results, map[string]models.FileRecord{}, 1, nil)

	if res.TotalAnomalies() != 0 {
		t.Fatalf("expected 0 anomalies for new oversize file, got %+v", res)
	}
}

func TestCompareWithBaselineRespectsWorkerCount(t *testing.T) {
	baseline := map[string]models.FileRecord{}
	results := []models.ScanResult{}
	for i := 0; i < 10; i++ {
		p := "/w/f" + string(rune('a'+i)) + ".php"
		baseline[p] = models.FileRecord{Path: p, Hash: "h"}
		results = append(results, models.ScanResult{Path: p, Hash: "h"})
	}
	// Satu worker pun harus menghasilkan hasil yang sama (deterministik).
	res := CompareWithBaseline(results, baseline, 1, nil)
	if res.TotalAnomalies() != 0 {
		t.Fatalf("expected 0 anomalies with 1 worker, got %+v", res)
	}
}

func TestCompareModeOnlyChangeIsModeChanged(t *testing.T) {
	baseline := map[string]models.FileRecord{
		"/w/wp-config.php": {Path: "/w/wp-config.php", Hash: "h", Mode: 0o644},
	}
	scanned := sr("/w/wp-config.php", "h")
	scanned.Mode = 0o777

	res := CompareWithBaseline([]models.ScanResult{scanned}, baseline, 2, nil)

	if len(res.ModeChanged) != 1 {
		t.Fatalf("expected 1 mode-changed, got %+v", res)
	}
	ev := res.ModeChanged[0]
	if ev.Action != models.ActionModeChanged || ev.OldMode != 0o644 || ev.NewMode != 0o777 {
		t.Fatalf("unexpected mode-changed event: %+v", ev)
	}
	if ev.OldHash != "h" || ev.NewHash != "h" {
		t.Fatalf("mode-only change must keep the same hash: %+v", ev)
	}
	if len(res.Modified) != 0 || res.TotalAnomalies() != 1 {
		t.Fatalf("mode-only change must not be MODIFIED: %+v", res)
	}
	if len(res.AllEvents()) != 1 || res.AllEvents()[0].Action != models.ActionModeChanged {
		t.Fatalf("AllEvents must include MODE_CHANGED: %+v", res.AllEvents())
	}
}

func TestCompareModeAdoptionForLegacyBaseline(t *testing.T) {
	// Baseline dari sebelum v1.5.0 tidak mencatat mode (Mode == 0):
	// siklus pertama mengadopsi mode tanpa event.
	baseline := map[string]models.FileRecord{
		"/w/legacy.php": {Path: "/w/legacy.php", Hash: "h"},
	}
	scanned := sr("/w/legacy.php", "h")
	scanned.Mode = 0o644

	res := CompareWithBaseline([]models.ScanResult{scanned}, baseline, 2, nil)

	if res.TotalAnomalies() != 0 {
		t.Fatalf("legacy baseline must not produce an event on first cycle: %+v", res)
	}
	if got, ok := res.ModeAdoptions["/w/legacy.php"]; !ok || got != 0o644 {
		t.Fatalf("expected mode adoption 0644, got %v (ok=%v)", got, ok)
	}
}

func TestCompareModeChangePlusHashChangeIsModified(t *testing.T) {
	baseline := map[string]models.FileRecord{
		"/w/a.php": {Path: "/w/a.php", Hash: "old", Mode: 0o644},
	}
	scanned := sr("/w/a.php", "new")
	scanned.Mode = 0o600

	res := CompareWithBaseline([]models.ScanResult{scanned}, baseline, 2, nil)

	if len(res.Modified) != 1 || len(res.ModeChanged) != 0 {
		t.Fatalf("hash+mode change must be a single MODIFIED: %+v", res)
	}
	if res.Modified[0].OldMode != 0o644 || res.Modified[0].NewMode != 0o600 {
		t.Fatalf("MODIFIED must record both modes: %+v", res.Modified[0])
	}
}

func TestCompareSkippedOversizeIsCounted(t *testing.T) {
	baseline := map[string]models.FileRecord{
		"/w/big.mp4": {Path: "/w/big.mp4", Hash: "old", Mode: 0o644},
	}
	results := []models.ScanResult{
		{Path: "/w/big.mp4", Mode: 0o644, Err: ErrFileOversize},
	}

	res := CompareWithBaseline(results, baseline, 2, nil)

	if res.SkippedOversize != 1 {
		t.Fatalf("expected 1 skipped oversize, got %d", res.SkippedOversize)
	}
	if res.TotalAnomalies() != 0 {
		t.Fatalf("oversize file must not be an anomaly: %+v", res)
	}
}
