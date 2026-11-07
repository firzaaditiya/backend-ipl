package ledger

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
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

	counts, err := l.GetDashboardCounts()
	if err != nil {
		t.Fatalf("GetDashboardCounts: %v", err)
	}
	if counts.Anomalies != 2 {
		t.Fatalf("expected release block excluded from anomaly count, got %d", counts.Anomalies)
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

func TestAdoptBaselineModesOnlyFillsZero(t *testing.T) {
	l := newTestLedger(t)

	legacy := record("/var/www/legacy.php", "h1")
	legacy.Mode = 0
	withMode := record("/var/www/with-mode.php", "h2")
	withMode.Mode = 0o600
	if err := l.SaveBaseline([]models.FileRecord{legacy, withMode}); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	if err := l.AdoptBaselineModes(map[string]uint32{
		"/var/www/legacy.php":    0o644,
		"/var/www/with-mode.php": 0o777, // tidak boleh menimpa mode yang sudah ada
		"/var/www/missing.php":   0o644, // tidak ada di baseline: diabaikan
	}); err != nil {
		t.Fatalf("AdoptBaselineModes: %v", err)
	}

	baseline, err := l.GetBaseline()
	if err != nil {
		t.Fatalf("GetBaseline: %v", err)
	}
	if baseline["/var/www/legacy.php"].Mode != 0o644 {
		t.Fatalf("legacy mode should be adopted as 0644, got %04o", baseline["/var/www/legacy.php"].Mode)
	}
	if baseline["/var/www/with-mode.php"].Mode != 0o600 {
		t.Fatalf("existing mode must not be overwritten, got %04o", baseline["/var/www/with-mode.php"].Mode)
	}
}

func TestRevokeTokenRoundTrip(t *testing.T) {
	l := newTestLedger(t)

	if l.IsTokenRevoked("jti-1") {
		t.Fatal("unknown jti must not be revoked")
	}
	if err := l.RevokeToken("jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if !l.IsTokenRevoked("jti-1") {
		t.Fatal("revoked jti must be reported revoked")
	}
	if l.IsTokenRevoked("jti-2") {
		t.Fatal("other jti must not be revoked")
	}
}

func TestRevokeTokenExpiredIsNotRevoked(t *testing.T) {
	l := newTestLedger(t)

	if err := l.RevokeToken("jti-old", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if l.IsTokenRevoked("jti-old") {
		t.Fatal("expired revocation must not block the token (it is dead by itself)")
	}
}

func TestAppendBlockRecordsModes(t *testing.T) {
	l := newTestLedger(t)

	ev := event("/var/www/wp-config.php", models.ActionModeChanged, "h", "h", true)
	ev.OldMode = 0o644
	ev.NewMode = 0o777
	block, err := l.AppendBlock(ev)
	if err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}
	if block.OldMode != 0o644 || block.NewMode != 0o777 {
		t.Fatalf("block must record modes, got old=%04o new=%04o", block.OldMode, block.NewMode)
	}
	if res := l.VerifyChain(); !res.Valid {
		t.Fatalf("chain must stay valid with mode fields: %s", res.Message)
	}
}

func TestAppendBlockUsesHashVersion3(t *testing.T) {
	l := newTestLedger(t)

	block, err := l.AppendBlock(event("/var/www/x.php", models.ActionCreated, "", "hash", true))
	if err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}
	if block.HashVersion != 3 {
		t.Fatalf("HashVersion = %d, want 3", block.HashVersion)
	}
	res := l.VerifyChain()
	if !res.Valid {
		t.Fatalf("expected valid chain, got: %s (block %s)", res.Message, res.FailedBlock)
	}
}

// putV1Block menulis satu blok v1 (HashVersion 0, hash dihitung dengan
// formula lama) langsung ke bucket, lalu memajukan sequence agar
// AppendBlock berikutnya tidak menimpanya.
func putV1Block(t *testing.T, l *Ledger, block models.Block) {
	t.Helper()
	block.HashVersion = 0
	block.BlockHash = calculateBlockHashV1(block)
	data, err := json.Marshal(block)
	if err != nil {
		t.Fatalf("marshal v1 block: %v", err)
	}
	if err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if err := b.Put([]byte("000000000001"), data); err != nil {
			return err
		}
		return b.SetSequence(1)
	}); err != nil {
		t.Fatalf("put v1 block: %v", err)
	}
}

func TestMixedV1V2V3ChainVerifies(t *testing.T) {
	l := newTestLedger(t)

	// Blok pertama ditulis dengan formula v1 (seperti 29 blok produksi).
	putV1Block(t, l, models.Block{
		ID:            "BLK-000001",
		Timestamp:     time.Date(2026, 11, 5, 17, 2, 48, 0, time.UTC),
		FilePath:      "/var/www/html/fim-sim-v15.php",
		Action:        models.ActionCreated,
		NewHash:       "9de72836",
		NewMode:       0o644,
		Quarantined:   true,
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})

	// Blok kedua ditulis dengan formula v2 (seperti blok instance uji T-02/T-03).
	putV2Block(t, l, models.Block{
		ID:            "BLK-000002",
		Timestamp:     time.Date(2026, 11, 5, 22, 34, 40, 0, time.UTC),
		FilePath:      "/var/www/html/fim-sim-v15.php",
		Action:        models.ActionModified,
		OldHash:       "9de72836",
		NewHash:       "7eb1dba8",
		OldMode:       0o644,
		NewMode:       0o644,
		Quarantined:   true,
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})

	// Blok berikutnya dibuat AppendBlock biasa (v3) di atas rantai v1→v2.
	if _, err := l.AppendBlock(event("/var/www/html/fim-sim-v15.php", models.ActionDeleted, "7eb1dba8", "", false)); err != nil {
		t.Fatalf("AppendBlock v3: %v", err)
	}

	res := l.VerifyChain()
	if !res.Valid {
		t.Fatalf("expected mixed v1->v2->v3 chain to verify, got: %s (block %s)", res.Message, res.FailedBlock)
	}
	if res.TotalBlocks != 3 {
		t.Fatalf("expected 3 blocks, got %d", res.TotalBlocks)
	}
	if res.HeadBlockID != "BLK-000003" {
		t.Fatalf("head = %s, want BLK-000003", res.HeadBlockID)
	}
}

// putV2Block menulis satu blok v2 (HashVersion 2, hash dihitung dengan
// formula v2) langsung ke bucket, lalu memajukan sequence. PrevBlockHash
// dihitung ulang dari blok sebelumnya agar rantai tetap utuh.
func putV2Block(t *testing.T, l *Ledger, block models.Block) {
	t.Helper()
	// Prev harus menunjuk hash blok sebelumnya (BLK-000001 v1).
	blocks, _, err := l.GetBlocks(0, 1)
	if err != nil || len(blocks) != 1 {
		t.Fatalf("get prev block: %v (blocks=%d)", err, len(blocks))
	}
	block.PrevBlockHash = blocks[0].BlockHash
	block.HashVersion = 2
	block.BlockHash = calculateBlockHashV2(block)
	data, err := json.Marshal(block)
	if err != nil {
		t.Fatalf("marshal v2 block: %v", err)
	}
	if err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if err := b.Put([]byte("000000000002"), data); err != nil {
			return err
		}
		return b.SetSequence(2)
	}); err != nil {
		t.Fatalf("put v2 block: %v", err)
	}
}

func TestV3TamperFailsAtExactBlock(t *testing.T) {
	tamper := func(t *testing.T, l *Ledger, blockID string, mutate func(*models.Block)) {
		t.Helper()
		if err := l.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketBlocks)
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var block models.Block
				if err := json.Unmarshal(v, &block); err != nil {
					return err
				}
				if block.ID != blockID {
					continue
				}
				mutate(&block)
				data, err := json.Marshal(block)
				if err != nil {
					return err
				}
				return b.Put(k, data)
			}
			return fmt.Errorf("block %s not found", blockID)
		}); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	}

	cases := []struct {
		name   string
		mutate func(*models.Block)
	}{
		{"OldMode", func(b *models.Block) { b.OldMode = 0o777 }},
		{"NewMode", func(b *models.Block) { b.NewMode = 0o600 }},
		{"QuarantineErr", func(b *models.Block) { b.QuarantineErr = "permission denied" }},
		{"Actor", func(b *models.Block) { b.Actor = "auditor (Auditor) dari 10.0.0.1" }},
		{"Detail", func(b *models.Block) { b.Detail = "alasan palsu" }},
		{"BaselineDigest", func(b *models.Block) {
			b.BaselineDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"BaselineCount", func(b *models.Block) { b.BaselineCount = 9999 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newTestLedger(t)
			for i := 0; i < 3; i++ {
				ev := event("/var/www/x.php", models.ActionModeChanged, "same", "same", true)
				ev.OldMode = 0o644
				ev.NewMode = 0o777
				ev.Actor = "admin (Super Admin) dari 127.0.0.1"
				ev.Detail = "pelepasan karantina: berkas dipastikan aman"
				if _, err := l.AppendBlock(ev); err != nil {
					t.Fatalf("AppendBlock %d: %v", i, err)
				}
			}
			tamper(t, l, "BLK-000002", tc.mutate)
			res := l.VerifyChain()
			if res.Valid {
				t.Fatalf("expected tampered %s to fail verification", tc.name)
			}
			if res.FailedBlock != "BLK-000002" {
				t.Fatalf("FailedBlock = %q, want BLK-000002", res.FailedBlock)
			}
		})
	}
}

func TestUnknownHashVersionRejected(t *testing.T) {
	l := newTestLedger(t)
	if _, err := l.AppendBlock(event("/var/www/x.php", models.ActionCreated, "", "hash", true)); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}
	if err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		k, v := b.Cursor().First()
		var block models.Block
		if err := json.Unmarshal(v, &block); err != nil {
			return err
		}
		block.HashVersion = 99
		data, _ := json.Marshal(block)
		return b.Put(k, data)
	}); err != nil {
		t.Fatalf("tamper version: %v", err)
	}
	res := l.VerifyChain()
	if res.Valid {
		t.Fatal("expected unknown hash_version to fail verification")
	}
	if res.FailedBlock != "BLK-000001" {
		t.Fatalf("FailedBlock = %q, want BLK-000001", res.FailedBlock)
	}
}

func TestPipeForgeryCannotCollide(t *testing.T) {
	ts := time.Date(2026, 11, 5, 22, 30, 0, 0, time.UTC)
	base := models.Block{
		ID:            "BLK-000001",
		Timestamp:     ts,
		OldHash:       "",
		NewHash:       "abc",
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Quarantined:   true,
	}
	// Dua tuple field berbeda yang string gabungan v1-nya identik:
	// "/var/www/a|b.php" + "|" + "CREATED" == "/var/www/a" + "|" + "b.php|CREATED".
	a := base
	a.FilePath = "/var/www/a|b.php"
	a.Action = models.ActionCreated
	b := base
	b.FilePath = "/var/www/a"
	b.Action = "b.php|" + models.ActionCreated

	if calculateBlockHashV1(a) != calculateBlockHashV1(b) {
		t.Fatal("v1 hash seharusnya bertabrakan untuk pasangan ini (itulah celahnya)")
	}
	a.HashVersion, b.HashVersion = 2, 2
	if calculateBlockHashV2(a) == calculateBlockHashV2(b) {
		t.Fatal("v2 hash tidak boleh bertabrakan untuk pasangan ini")
	}
}

func TestBaselineDigestIsStableAndSensitive(t *testing.T) {
	records := map[string]models.FileRecord{
		"/var/www/a.php": {Path: "/var/www/a.php", Hash: "aaa", Mode: 0o644, Size: 100},
		"/var/www/b.php": {Path: "/var/www/b.php", Hash: "bbb", Mode: 0o600, Size: 200},
	}
	d1, n1 := baselineDigestFor(records)
	if n1 != 2 {
		t.Fatalf("count = %d, want 2", n1)
	}
	// Urutan map tidak memengaruhi digest (diurutkan berdasarkan path).
	d2, _ := baselineDigestFor(records)
	if d1 != d2 {
		t.Fatal("digest must be deterministic")
	}
	changed := map[string]models.FileRecord{
		"/var/www/a.php": {Path: "/var/www/a.php", Hash: "aaa", Mode: 0o644, Size: 100},
		"/var/www/b.php": {Path: "/var/www/b.php", Hash: "ccc", Mode: 0o600, Size: 200},
	}
	if d, _ := baselineDigestFor(changed); d == d1 {
		t.Fatal("changing one hash must change the digest")
	}
	changedMode := map[string]models.FileRecord{
		"/var/www/a.php": {Path: "/var/www/a.php", Hash: "aaa", Mode: 0o644, Size: 100},
		"/var/www/b.php": {Path: "/var/www/b.php", Hash: "bbb", Mode: 0o644, Size: 200},
	}
	if d, _ := baselineDigestFor(changedMode); d == d1 {
		t.Fatal("changing one mode must change the digest")
	}
	changedSize := map[string]models.FileRecord{
		"/var/www/a.php": {Path: "/var/www/a.php", Hash: "aaa", Mode: 0o644, Size: 101},
		"/var/www/b.php": {Path: "/var/www/b.php", Hash: "bbb", Mode: 0o600, Size: 200},
	}
	if d, _ := baselineDigestFor(changedSize); d == d1 {
		t.Fatal("changing one size must change the digest")
	}
	// Baseline kosong punya digest yang terdefinisi (hash dari string kosong).
	dEmpty, nEmpty := baselineDigestFor(nil)
	if nEmpty != 0 || dEmpty == "" {
		t.Fatalf("empty baseline: digest=%q count=%d", dEmpty, nEmpty)
	}
}

func TestVerifyBaselineDigestDetectsDirectEdit(t *testing.T) {
	l := newTestLedger(t)

	records := []models.FileRecord{
		{Path: "/var/www/a.php", Hash: "aaa", Mode: 0o644, Size: 100, ModTime: time.Now(), ScannedAt: time.Now()},
		{Path: "/var/www/b.php", Hash: "bbb", Mode: 0o600, Size: 200, ModTime: time.Now(), ScannedAt: time.Now()},
	}
	if err := l.SaveBaseline(records); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	digest, count, err := l.BaselineDigest()
	if err != nil {
		t.Fatalf("BaselineDigest: %v", err)
	}
	initBlock, err := l.AppendBlock(models.AnomalyEvent{
		FilePath:       models.AdminBlockPath,
		Action:         models.ActionBaselineInit,
		Actor:          "admin (Super Admin) dari 127.0.0.1",
		Detail:         "baseline dibuat: 2 berkas",
		BaselineDigest: digest,
		BaselineCount:  count,
	})
	if err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}
	if initBlock.HashVersion != 3 {
		t.Fatalf("HashVersion = %d, want 3", initBlock.HashVersion)
	}
	if initBlock.BaselineDigest != digest || initBlock.BaselineCount != 2 {
		t.Fatalf("block digest = %q/%d, want %q/2", initBlock.BaselineDigest, initBlock.BaselineCount, digest)
	}

	// Baseline belum diubah: verifikasi cocok.
	res, err := l.VerifyBaselineDigest()
	if err != nil {
		t.Fatalf("VerifyBaselineDigest: %v", err)
	}
	if !res.Match {
		t.Fatalf("expected match, got: %s", res.Message)
	}
	if res.BlockID != initBlock.ID {
		t.Fatalf("BlockID = %q, want %q", res.BlockID, initBlock.ID)
	}

	// Edit SATU entri baseline langsung di Bbolt (simulasi root yang
	// memanipulasi baseline tanpa lewat endpoint resmi).
	if err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBaseline)
		v := b.Get([]byte("/var/www/b.php"))
		var rec models.FileRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return err
		}
		rec.Hash = "hash-palsu"
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte("/var/www/b.php"), data)
	}); err != nil {
		t.Fatalf("tamper baseline: %v", err)
	}

	res, err = l.VerifyBaselineDigest()
	if err != nil {
		t.Fatalf("VerifyBaselineDigest: %v", err)
	}
	if res.Match {
		t.Fatal("expected mismatch after a direct baseline edit")
	}
	if res.BlockID != initBlock.ID {
		t.Fatalf("BlockID = %q, want %q", res.BlockID, initBlock.ID)
	}
	if res.ExpectedDigest == res.ActualDigest {
		t.Fatal("expected different digests after tampering")
	}
	if res.ExpectedCount != 2 || res.ActualCount != 2 {
		t.Fatalf("counts = %d/%d, want 2/2", res.ExpectedCount, res.ActualCount)
	}
	// Rantai sendiri tetap valid: yang rusak adalah baseline, bukan blok.
	if vres := l.VerifyChain(); !vres.Valid {
		t.Fatalf("chain must stay valid (baseline tampering is outside the chain): %s", vres.Message)
	}
}

func TestGetQuarantineModePrefersChain(t *testing.T) {
	l := newTestLedger(t)
	path := "/var/www/shell.php"

	if _, err := l.AppendBlock(models.AnomalyEvent{
		FilePath:    path,
		Action:      models.ActionCreated,
		NewHash:     "abc",
		NewMode:     0o644,
		Quarantined: true,
	}); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}

	// Bucket diisi nilai yang SALAH (simulasi manipulasi langsung).
	if err := l.RecordQuarantineMode(path, 0o600); err != nil {
		t.Fatalf("RecordQuarantineMode: %v", err)
	}

	mode, found, err := l.GetQuarantineMode(path)
	if err != nil {
		t.Fatalf("GetQuarantineMode: %v", err)
	}
	if !found {
		t.Fatal("expected mode to be found")
	}
	if mode != 0o644 {
		t.Fatalf("mode = %04o, want 0644 (chain must win over the tampered bucket)", mode)
	}

	// Fallback: path yang hanya ada di bucket (tanpa blok rantai).
	other := "/var/www/lama.php"
	if err := l.RecordQuarantineMode(other, 0o640); err != nil {
		t.Fatalf("RecordQuarantineMode: %v", err)
	}
	mode, found, err = l.GetQuarantineMode(other)
	if err != nil || !found || mode != 0o640 {
		t.Fatalf("bucket fallback: mode=%04o found=%v err=%v", mode, found, err)
	}
}

func TestVerifyBlocksMixedChain(t *testing.T) {
	l := newTestLedger(t)

	// Rantai campuran v1 -> v2 -> v3 (dibangun lewat AppendBlock; versi
	// blok ditentukan kode AppendBlock saat ini, jadi jalankan dengan
	// helper putV1Block/putV2Block untuk blok lamanya).
	putV1Block(t, l, models.Block{
		ID:            "BLK-000001",
		Timestamp:     time.Date(2026, 11, 5, 17, 2, 48, 0, time.UTC),
		FilePath:      "/var/www/a.php",
		Action:        models.ActionCreated,
		NewHash:       "aaa",
		NewMode:       0o644,
		Quarantined:   true,
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	putV2Block(t, l, models.Block{
		ID:            "BLK-000002",
		Timestamp:     time.Date(2026, 11, 5, 22, 34, 40, 0, time.UTC),
		FilePath:      "/var/www/b.php",
		Action:        models.ActionCreated,
		NewHash:       "bbb",
		NewMode:       0o644,
		Quarantined:   true,
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if _, err := l.AppendBlock(event("/var/www/c.php", models.ActionCreated, "", "ccc", false)); err != nil {
		t.Fatalf("AppendBlock: %v", err)
	}

	blocks, _, err := l.GetBlocks(0, 100)
	if err != nil {
		t.Fatalf("GetBlocks: %v", err)
	}
	// GetBlocks mengembalikan urutan terbaru-dulu; balik untuk VerifyBlocks.
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}

	res := VerifyBlocks(blocks)
	if !res.Valid {
		t.Fatalf("VerifyBlocks mixed chain = invalid: %s", res.Message)
	}
	if res.TotalBlocks != 3 || res.HeadBlockID != "BLK-000003" {
		t.Fatalf("VerifyBlocks = %+v, want 3 blocks head BLK-000003", res)
	}
}

func TestVerifyBlocksDetectsTampering(t *testing.T) {
	l := newTestLedger(t)
	for i := 0; i < 3; i++ {
		if _, err := l.AppendBlock(event("/var/www/x.php", models.ActionCreated, "", "hash", false)); err != nil {
			t.Fatalf("AppendBlock: %v", err)
		}
	}
	blocks, _, err := l.GetBlocks(0, 100)
	if err != nil {
		t.Fatalf("GetBlocks: %v", err)
	}
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}

	blocks[1].NewHash = "hash-palsu"
	res := VerifyBlocks(blocks)
	if res.Valid {
		t.Fatal("VerifyBlocks must fail on a tampered block")
	}
	if res.FailedBlock != "BLK-000002" {
		t.Fatalf("FailedBlock = %q, want BLK-000002", res.FailedBlock)
	}
}

func TestVerifyBlocksCannotDetectTailTruncation(t *testing.T) {
	// BATAS YANG JUJUR (T-06): menghapus blok-blok terakhir menghasilkan
	// rantai yang lebih pendek tetapi tetap utuh — verifikasi lokal
	// TIDAK bisa mendeteksinya. Test ini mengunci perilaku itu agar
	// tidak ada yang mengklaim sebaliknya; yang mendeteksi pemotongan
	// adalah perbandingan head hash dengan jangkar eksternal (Telegram).
	l := newTestLedger(t)
	for i := 0; i < 4; i++ {
		if _, err := l.AppendBlock(event("/var/www/x.php", models.ActionCreated, "", "hash", false)); err != nil {
			t.Fatalf("AppendBlock: %v", err)
		}
	}
	blocks, _, err := l.GetBlocks(0, 100)
	if err != nil {
		t.Fatalf("GetBlocks: %v", err)
	}
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}

	truncated := blocks[:2]
	res := VerifyBlocks(truncated)
	if !res.Valid {
		t.Fatalf("truncated chain must still verify (this is the known limit): %s", res.Message)
	}
	if res.HeadBlockID != "BLK-000002" {
		t.Fatalf("truncated head = %q, want BLK-000002", res.HeadBlockID)
	}
	// Jangkar eksternal (head hash dari sebelum pemotongan) TIDAK cocok
	// dengan head hash rantai yang terpotong — itulah deteksinya.
	full := VerifyBlocks(blocks)
	if full.HeadHash == res.HeadHash {
		t.Fatal("truncated head hash must differ from the full-chain anchor")
	}
}

func TestRecordVerificationRoundTrip(t *testing.T) {
	l := newTestLedger(t)
	if got, err := l.GetLastVerification(); err != nil || got != nil {
		t.Fatalf("GetLastVerification before any record = %v, %v; want nil, nil", got, err)
	}
	lv := models.LastVerification{
		VerifiedAt:      time.Now().UTC().Truncate(time.Second),
		ChainValid:      true,
		ChainMessage:    "chain intact",
		HeadBlockID:     "BLK-000005",
		HeadHash:        strings.Repeat("c", 64),
		TotalBlocks:     5,
		BaselineMatch:   true,
		BaselineBlockID: "BLK-000004",
		BaselineMessage: "baseline cocok dengan blok baseline terakhir",
	}
	if err := l.RecordVerification(lv); err != nil {
		t.Fatalf("RecordVerification: %v", err)
	}
	got, err := l.GetLastVerification()
	if err != nil {
		t.Fatalf("GetLastVerification: %v", err)
	}
	if got == nil || got.HeadBlockID != "BLK-000005" || !got.ChainValid || !got.BaselineMatch {
		t.Fatalf("GetLastVerification = %+v", got)
	}
}
