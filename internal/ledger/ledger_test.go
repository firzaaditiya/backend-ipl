package ledger

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
	bolt "go.etcd.io/bbolt"
)

func newTestLedger(t *testing.T) *Ledger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	l, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func record(path, hash string) models.FileRecord {
	return models.FileRecord{Path: path, Hash: hash, Size: 10, ModTime: time.Now(), ScannedAt: time.Now()}
}

func event(path, action, oldHash, newHash string, quarantined bool) models.AnomalyEvent {
	return models.AnomalyEvent{
		FilePath:    path,
		Action:      action,
		OldHash:     oldHash,
		NewHash:     newHash,
		Quarantined: quarantined,
	}
}

func TestBaselineSaveAndCount(t *testing.T) {
	l := newTestLedger(t)

	if err := l.SaveBaseline([]models.FileRecord{
		record("/var/www/a.php", "aaa"),
		record("/var/www/b.php", "bbb"),
	}); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	count, err := l.GetBaselineCount()
	if err != nil {
		t.Fatalf("GetBaselineCount: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 baseline entries, got %d", count)
	}

	// Re-init harus mengganti (bukan menambah) baseline lama.
	if err := l.SaveBaseline([]models.FileRecord{record("/var/www/c.php", "ccc")}); err != nil {
		t.Fatalf("SaveBaseline replace: %v", err)
	}
	count, _ = l.GetBaselineCount()
	if count != 1 {
		t.Fatalf("expected baseline replaced to 1 entry, got %d", count)
	}
}

func TestVerifyChainValid(t *testing.T) {
	l := newTestLedger(t)

	for i := 0; i < 3; i++ {
		if _, err := l.AppendBlock(event("/var/www/x.php", models.ActionModified, "old", "new", true)); err != nil {
			t.Fatalf("AppendBlock %d: %v", i, err)
		}
	}

	res := l.VerifyChain()
	if !res.Valid {
		t.Fatalf("expected valid chain, got message: %s (block %s)", res.Message, res.FailedBlock)
	}
	if res.TotalBlocks != 3 {
		t.Fatalf("expected 3 blocks, got %d", res.TotalBlocks)
	}
}

func TestVerifyChainDetectsTampering(t *testing.T) {
	l := newTestLedger(t)

	for i := 0; i < 3; i++ {
		if _, err := l.AppendBlock(event("/var/www/x.php", models.ActionCreated, "", "hash", false)); err != nil {
			t.Fatalf("AppendBlock: %v", err)
		}
	}

	// Ubah isi blok pertama tanpa memperbarui block_hash (simulasi manipulasi).
	err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		k, v := b.Cursor().First()
		var block models.Block
		if err := json.Unmarshal(v, &block); err != nil {
			return err
		}
		block.FilePath = "/var/www/backdoor.php"
		data, _ := json.Marshal(block)
		return b.Put(k, data)
	})
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}

	res := l.VerifyChain()
	if res.Valid {
		t.Fatal("expected tampered chain to be invalid")
	}
	if res.FailedBlock == "" {
		t.Fatal("expected failed block id to be reported")
	}
}

func TestQuarantineStateHelpers(t *testing.T) {
	l := newTestLedger(t)

	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionCreated, "", "h1", true)); err != nil {
		t.Fatalf("append a1: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/b.php", models.ActionCreated, "", "h2", false)); err != nil {
		t.Fatalf("append b1: %v", err)
	}

	count, err := l.GetQuarantinedFileCount()
	if err != nil {
		t.Fatalf("GetQuarantinedFileCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 quarantined file, got %d", count)
	}

	// /a.php dirilis: blok terakhir untuk path ini tidak terkarantina lagi.
	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionModified, "h1", "h3", false)); err != nil {
		t.Fatalf("append a2: %v", err)
	}
	count, _ = l.GetQuarantinedFileCount()
	if count != 0 {
		t.Fatalf("expected 0 quarantined files after release, got %d", count)
	}

	if q, _ := l.IsCurrentlyQuarantined("/var/www/a.php"); q {
		t.Fatal("expected a.php to be released")
	}

	// File yang dihapus tidak dihitung sebagai terkarantina.
	if _, err := l.AppendBlock(event("/var/www/b.php", models.ActionDeleted, "h2", "", false)); err != nil {
		t.Fatalf("append b2: %v", err)
	}
	if q, _ := l.IsCurrentlyQuarantined("/var/www/b.php"); q {
		t.Fatal("expected deleted file to not be quarantined")
	}
}

func TestQuarantinedFiles(t *testing.T) {
	l := newTestLedger(t)

	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionCreated, "", "h1", true)); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if err := l.RecordQuarantineMode("/var/www/a.php", 0o640); err != nil {
		t.Fatalf("record mode a: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/b.php", models.ActionCreated, "", "h2", true)); err != nil {
		t.Fatalf("append b: %v", err)
	}
	// b.php dikarantina sebelum pencatatan izin (tanpa RecordQuarantineMode):
	// daftar tetap memuatnya, dengan OriginalMode nil.
	files, err := l.QuarantinedFiles()
	if err != nil {
		t.Fatalf("QuarantinedFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 quarantined files, got %d", len(files))
	}
	if files[0].FilePath != "/var/www/a.php" || files[1].FilePath != "/var/www/b.php" {
		t.Fatalf("expected sorted paths a,b, got %+v", files)
	}
	if files[0].OriginalMode == nil || *files[0].OriginalMode != 0o640 {
		t.Fatalf("expected a.php original mode 0640, got %+v", files[0])
	}
	if files[1].OriginalMode != nil {
		t.Fatalf("expected b.php original mode nil, got %+v", files[1])
	}

	// Setelah RELEASED, a.php keluar dari daftar.
	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionReleased, "", "", false)); err != nil {
		t.Fatalf("append released: %v", err)
	}
	files, _ = l.QuarantinedFiles()
	if len(files) != 1 || files[0].FilePath != "/var/www/b.php" {
		t.Fatalf("expected only b.php quarantined, got %+v", files)
	}
}

func TestMetricsRetentionCap(t *testing.T) {
	l := newTestLedger(t)
	l.maxMetricEntries = 3

	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := l.SaveMetric(models.ScanMetric{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			ElapsedMs: int64(i),
		}); err != nil {
			t.Fatalf("SaveMetric %d: %v", i, err)
		}
	}

	metrics, err := l.GetMetrics(0)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics after retention, got %d", len(metrics))
	}
	// Sisa harus yang paling baru (elapsed 2,3,4).
	if metrics[0].ElapsedMs != 2 || metrics[2].ElapsedMs != 4 {
		t.Fatalf("expected latest metrics retained, got %+v", metrics)
	}
}

func TestVerifyChainExposesHeadAnchor(t *testing.T) {
	l := newTestLedger(t)

	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionCreated, "", "h1", true)); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	last, err := l.AppendBlock(event("/var/www/b.php", models.ActionModified, "h1", "h2", true))
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}

	res := l.VerifyChain()
	if !res.Valid {
		t.Fatalf("expected valid chain, got %s", res.Message)
	}
	if res.HeadBlockID != last.ID || res.HeadHash != last.BlockHash {
		t.Fatalf("unexpected head anchor: id=%q hash=%q (want %q/%q)",
			res.HeadBlockID, res.HeadHash, last.ID, last.BlockHash)
	}
	if res.HeadHash == genesisPrevHash {
		t.Fatal("expected head hash to differ from genesis")
	}

	exp, err := l.ExportAll(false)
	if err != nil {
		t.Fatalf("ExportAll: %v", err)
	}
	if exp.HeadBlockID != last.ID || exp.HeadHash != last.BlockHash {
		t.Fatalf("export missing head anchor: %+v", exp)
	}
}

func TestAnomalyCountExcludesReleaseRecords(t *testing.T) {
	l := newTestLedger(t)

	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionCreated, "", "h1", true)); err != nil {
		t.Fatalf("append created: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/b.php", models.ActionModified, "h1", "h2", true)); err != nil {
		t.Fatalf("append modified: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionReleased, "", "", false)); err != nil {
		t.Fatalf("append released: %v", err)
	}

	blocks, err := l.GetBlockCount()
	if err != nil {
		t.Fatalf("GetBlockCount: %v", err)
	}
	if blocks != 3 {
		t.Fatalf("expected 3 ledger blocks, got %d", blocks)
	}

	anomalies, err := l.GetAnomalyCount()
	if err != nil {
		t.Fatalf("GetAnomalyCount: %v", err)
	}
	if anomalies != 2 {
		t.Fatalf("expected release block excluded from anomaly count, got %d", anomalies)
	}

	// Release menutup status karantina path tersebut.
	if q, _ := l.IsCurrentlyQuarantined("/var/www/a.php"); q {
		t.Fatal("expected a.php to be marked released")
	}
	count, _ := l.GetQuarantinedFileCount()
	if count != 1 {
		t.Fatalf("expected only b.php still quarantined, got %d", count)
	}
	if res := l.VerifyChain(); !res.Valid {
		t.Fatalf("chain must stay valid after release record: %s", res.Message)
	}
}

func TestGetDashboardCountsSinglePass(t *testing.T) {
	l := newTestLedger(t)

	if err := l.SaveBaseline([]models.FileRecord{
		record("/var/www/a.php", "a1"),
		record("/var/www/b.php", "b1"),
		record("/var/www/c.php", "c1"),
	}); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionCreated, "", "a1", true)); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/b.php", models.ActionModified, "b1", "b2", true)); err != nil {
		t.Fatalf("append b: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/d.php", models.ActionDeleted, "d1", "", false)); err != nil {
		t.Fatalf("append d: %v", err)
	}
	if _, err := l.AppendBlock(event("/var/www/a.php", models.ActionReleased, "", "", false)); err != nil {
		t.Fatalf("append release: %v", err)
	}

	counts, err := l.GetDashboardCounts()
	if err != nil {
		t.Fatalf("GetDashboardCounts: %v", err)
	}

	if counts.TotalFiles != 3 {
		t.Fatalf("TotalFiles = %d, want 3", counts.TotalFiles)
	}
	if counts.TotalBlocks != 4 {
		t.Fatalf("TotalBlocks = %d, want 4", counts.TotalBlocks)
	}
	if counts.Anomalies != 3 {
		t.Fatalf("Anomalies = %d, want 3 (RELEASED excluded)", counts.Anomalies)
	}
	if counts.QuarantinedFiles != 1 {
		t.Fatalf("QuarantinedFiles = %d, want 1 (only b.php)", counts.QuarantinedFiles)
	}
}

func TestSearchBlocksNewestFirstAndPaginated(t *testing.T) {
	l := newTestLedger(t)

	for i := 0; i < 5; i++ {
		path := fmt.Sprintf("/var/www/f%d.php", i)
		if _, err := l.AppendBlock(event(path, models.ActionModified, "old", "new", true)); err != nil {
			t.Fatalf("append %s: %v", path, err)
		}
	}
	if _, err := l.AppendBlock(event("/var/www/created.php", models.ActionCreated, "", "new", true)); err != nil {
		t.Fatalf("append created: %v", err)
	}

	page, total, err := l.SearchBlocks("", models.ActionModified, 0, 2)
	if err != nil {
		t.Fatalf("SearchBlocks page 1: %v", err)
	}
	if total != 5 || len(page) != 2 {
		t.Fatalf("page 1: total=%d len=%d, want 5/2", total, len(page))
	}
	if page[0].FilePath != "/var/www/f4.php" || page[1].FilePath != "/var/www/f3.php" {
		t.Fatalf("expected newest-first order, got %s, %s", page[0].FilePath, page[1].FilePath)
	}

	page, total, err = l.SearchBlocks("", models.ActionModified, 4, 2)
	if err != nil {
		t.Fatalf("SearchBlocks page 3: %v", err)
	}
	if total != 5 || len(page) != 1 || page[0].FilePath != "/var/www/f0.php" {
		t.Fatalf("page 3 mismatch: total=%d page=%+v", total, page)
	}

	page, total, err = l.SearchBlocks("f2", "", 0, 10)
	if err != nil {
		t.Fatalf("SearchBlocks query: %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].FilePath != "/var/www/f2.php" {
		t.Fatalf("query mismatch: total=%d page=%+v", total, page)
	}

	page, total, err = l.SearchBlocks("tidak-ada", "", 0, 10)
	if err != nil {
		t.Fatalf("SearchBlocks empty: %v", err)
	}
	if total != 0 || page == nil || len(page) != 0 {
		t.Fatalf("expected non-nil empty slice, got total=%d page=%#v", total, page)
	}
}
