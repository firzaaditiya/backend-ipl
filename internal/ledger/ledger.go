package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketBlocks   = []byte("blocks")
	bucketBaseline = []byte("baseline")
	bucketMeta     = []byte("meta")
	bucketMetrics  = []byte("metrics")
)

const genesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// maxMetricEntries membatasi jumlah titik metrik yang disimpan. Metrik adalah
// data time-series untuk grafik; menyimpannya tanpa batas akan membuat DB
// tumbuh terus-menerus. Siklus paling lama dihapus saat melewati batas ini.
const maxMetricEntries = 5000

type Ledger struct {
	db *bolt.DB
	// maxMetricEntries membatasi titik metrik yang disimpan (field, bukan const,
	// agar bisa diperkecil saat pengujian).
	maxMetricEntries int
}

func New(dbPath string) (*Ledger, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// File DB sudah ada sebelumnya bisa saja longgar; paksa 0600 di Unix agar
	// user web tidak bisa membaca baseline atau menulis ledger.
	if runtime.GOOS != "windows" {
		if chmodErr := os.Chmod(dbPath, 0o600); chmodErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to restrict database permissions: %w", chmodErr)
		}
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketBlocks, bucketBaseline, bucketMeta, bucketMetrics} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}

	return &Ledger{db: db, maxMetricEntries: maxMetricEntries}, nil
}

func (l *Ledger) Close() error {
	return l.db.Close()
}

// ---------------------------------------------------------------------------
// Baseline operations
// ---------------------------------------------------------------------------

func (l *Ledger) SaveBaseline(records []models.FileRecord) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(bucketBaseline); err != nil && err != bolt.ErrBucketNotFound {
			return err
		}
		b, err := tx.CreateBucket(bucketBaseline)
		if err != nil {
			return err
		}

		for _, record := range records {
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(record.Path), data); err != nil {
				return err
			}
		}

		meta := tx.Bucket(bucketMeta)
		return meta.Put([]byte("baseline_time"), []byte(time.Now().Format(time.RFC3339)))
	})
}

func (l *Ledger) GetBaseline() (map[string]models.FileRecord, error) {
	baseline := make(map[string]models.FileRecord)

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBaseline)
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var record models.FileRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			baseline[string(k)] = record
			return nil
		})
	})

	return baseline, err
}

func (l *Ledger) GetBaselineCount() (int, error) {
	var count int
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBaseline)
		if b == nil {
			return nil
		}
		count = countKeys(b)
		return nil
	})
	return count, err
}

// UpdateBaselineEntry memperbarui hash file di baseline (untuk kasus MODIFIED/CREATED)
func (l *Ledger) UpdateBaselineEntry(record models.FileRecord) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBaseline)
		if b == nil {
			return nil
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return b.Put([]byte(record.Path), data)
	})
}

// RemoveBaselineEntry menghapus file dari baseline (untuk kasus DELETED)
func (l *Ledger) RemoveBaselineEntry(path string) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBaseline)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(path))
	})
}

// GetBaselineTime mengembalikan timestamp baseline terakhir (RFC3339) atau string kosong.
func (l *Ledger) GetBaselineTime() (string, error) {
	var t string
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if b == nil {
			return nil
		}
		v := b.Get([]byte("baseline_time"))
		if v != nil {
			t = string(v)
		}
		return nil
	})
	return t, err
}

// ---------------------------------------------------------------------------
// Block (hash-chain) operations
// ---------------------------------------------------------------------------

func (l *Ledger) AppendBlock(event models.AnomalyEvent) (*models.Block, error) {
	var block models.Block

	err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)

		seq, err := b.NextSequence()
		if err != nil {
			return err
		}

		prevHash, err := lastBlockHash(b)
		if err != nil {
			return fmt.Errorf("read previous block: %w", err)
		}

		block = models.Block{
			ID:            fmt.Sprintf("BLK-%06d", seq),
			Timestamp:     time.Now(),
			FilePath:      event.FilePath,
			Action:        event.Action,
			OldHash:       event.OldHash,
			NewHash:       event.NewHash,
			Quarantined:   event.Quarantined,
			QuarantineErr: event.QuarantineErr,
			PrevBlockHash: prevHash,
		}

		block.BlockHash = calculateBlockHash(block)

		data, err := json.Marshal(block)
		if err != nil {
			return err
		}

		key := fmt.Sprintf("%012d", seq)
		return b.Put([]byte(key), data)
	})

	if err != nil {
		return nil, err
	}

	return &block, nil
}

func (l *Ledger) GetBlocks(offset, limit int) ([]models.Block, int, error) {
	blocks := make([]models.Block, 0, limit)
	var total int

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}

		total = countKeys(b)

		cursor := b.Cursor()
		i := 0
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			if i < offset {
				i++
				continue
			}
			if len(blocks) >= limit {
				break
			}

			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}
			blocks = append(blocks, block)
			i++
		}

		return nil
	})

	return blocks, total, err
}

// SearchBlocks mencari block berdasarkan teks (path, ID, aksi) dan/atau
// filter aksi (MODIFIED, CREATED, DELETED). Parameter query maupun action
// boleh kosong; jika action diisi, hasil dibatasi pada aksi tersebut.
func (l *Ledger) SearchBlocks(query, action string, offset, limit int) ([]models.Block, int, error) {
	blocks := make([]models.Block, 0, limit)
	var total int
	action = strings.ToUpper(strings.TrimSpace(action))

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}

		// Iterasi dari blok terbaru. Hanya blok pada window halaman yang
		// disimpan di memori, sehingga pencarian tetap ringan pada ledger besar.
		cursor := b.Cursor()
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}
			textMatch := query == "" ||
				containsIgnoreCase(block.FilePath, query) ||
				containsIgnoreCase(block.Action, query) ||
				containsIgnoreCase(block.ID, query)
			actionMatch := action == "" || strings.EqualFold(block.Action, action)
			if !textMatch || !actionMatch {
				continue
			}

			if total >= offset && len(blocks) < limit {
				blocks = append(blocks, block)
			}
			total++
		}
		return nil
	})

	return blocks, total, err
}

// GetBlockCount mengembalikan jumlah seluruh block, termasuk catatan
// pelepasan karantina.
func (l *Ledger) GetBlockCount() (int, error) {
	var count int
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}
		count = countKeys(b)
		return nil
	})
	return count, err
}

// GetAnomalyCount menghitung temuan pemindaian saja (CREATED/MODIFIED/DELETED).
// Block RELEASED adalah catatan tindakan admin, bukan anomali file, sehingga
// tidak boleh menggelembungkan angka "total anomali" di dashboard.
func (l *Ledger) GetAnomalyCount() (int, error) {
	count := 0
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				return nil
			}
			if block.Action != models.ActionReleased {
				count++
			}
			return nil
		})
	})
	return count, err
}

// GetCurrentlyQuarantinedPaths mengembalikan path yang status TERAKHIR-nya
// masih dikarantina. Dipakai scanner untuk tidak melaporkan file yang sengaja
// dibuat tidak terbaca oleh karantina sebagai anomali baru setiap siklus.
func (l *Ledger) GetCurrentlyQuarantinedPaths() (map[string]bool, error) {
	seen := make(map[string]struct{})
	out := make(map[string]bool)

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}

		cursor := b.Cursor()
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}
			if _, ok := seen[block.FilePath]; ok {
				continue
			}
			seen[block.FilePath] = struct{}{}
			if block.Quarantined && block.Action != models.ActionDeleted {
				out[block.FilePath] = true
			}
		}
		return nil
	})

	return out, err
}

// GetQuarantinedFileCount menghitung file yang status TERAKHIR-nya masih
// dikarantina. Berbeda dari GetAffectedFileCount lama, hitungan ini tidak
// terus bertambah setelah baseline diperbarui otomatis.
func (l *Ledger) GetQuarantinedFileCount() (int, error) {
	seen := make(map[string]struct{})
	count := 0

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}

		cursor := b.Cursor()
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}
			if _, ok := seen[block.FilePath]; ok {
				continue
			}
			seen[block.FilePath] = struct{}{}
			if block.Quarantined && block.Action != models.ActionDeleted {
				count++
			}
		}
		return nil
	})

	return count, err
}

// DashboardCounts adalah ringkasan satu-pass untuk halaman dashboard.
// Semua angka dihitung dalam satu transaksi Bbolt agar dashboard tidak
// melakukan tiga pembacaan terpisah pada setiap refresh/event realtime.
type DashboardCounts struct {
	TotalFiles       int
	TotalBlocks      int
	Anomalies        int
	QuarantinedFiles int
}

// GetDashboardCounts menghitung baseline, total blok, anomali, dan file yang
// masih dikarantina dalam satu transaksi.
func (l *Ledger) GetDashboardCounts() (DashboardCounts, error) {
	var counts DashboardCounts

	err := l.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(bucketBaseline); b != nil {
			counts.TotalFiles = countKeys(b)
		}

		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}
		counts.TotalBlocks = countKeys(b)

		seen := make(map[string]struct{})
		cursor := b.Cursor()
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}

			if block.Action != models.ActionReleased {
				counts.Anomalies++
			}

			if _, ok := seen[block.FilePath]; ok {
				continue
			}
			seen[block.FilePath] = struct{}{}
			if block.Quarantined && block.Action != models.ActionDeleted {
				counts.QuarantinedFiles++
			}
		}
		return nil
	})

	return counts, err
}

// IsCurrentlyQuarantined memeriksa status karantina terakhir untuk satu path.
func (l *Ledger) IsCurrentlyQuarantined(path string) (bool, error) {
	var result bool

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}

		cursor := b.Cursor()
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}
			if block.FilePath != path {
				continue
			}
			result = block.Quarantined && block.Action != models.ActionDeleted
			return nil
		}
		return nil
	})

	return result, err
}

// VerifyResult adalah hasil detail dari VerifyChain.
//
// HeadBlockID dan HeadHash adalah "anchor" blok terakhir. Nilai ini dapat
// dibandingkan dengan salinan export/backup di luar server. Hash-chain lokal
// tidak bisa mendeteksi penghapusan blok-blok TERAKHIR (tail truncation) —
// membandingkan head dengan salinan off-box adalah mitigasinya.
type VerifyResult struct {
	Valid       bool      `json:"valid"`
	Message     string    `json:"message"`
	FailedBlock string    `json:"failed_block,omitempty"`
	TotalBlocks int       `json:"total_blocks"`
	HeadBlockID string    `json:"head_block_id,omitempty"`
	HeadHash    string    `json:"head_hash"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// VerifyChain memeriksa integritas rantai blok secara menyeluruh:
//  1. Setiap block[N].prev_block_hash == block[N-1].block_hash
//  2. Setiap block_hash == SHA256(rekalkulasi dari isinya)
//
// Jika ada kegagalan, FailedBlock diisi dengan ID block yang bermasalah.
func (l *Ledger) VerifyChain() VerifyResult {
	res := VerifyResult{
		VerifiedAt: time.Now().UTC(),
		HeadHash:   genesisPrevHash,
	}

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}
		res.TotalBlocks = countKeys(b)
		if res.TotalBlocks == 0 {
			return nil
		}

		prevHash := genesisPrevHash
		cursor := b.Cursor()

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				res.FailedBlock = string(k)
				return fmt.Errorf("invalid block data at key %s", string(k))
			}

			// Key harus berupa sequence dan cocok dengan ID blok.
			seq, err := strconv.Atoi(string(k))
			if err != nil || block.ID != fmt.Sprintf("BLK-%06d", seq) {
				res.FailedBlock = block.ID
				return fmt.Errorf("block %s has inconsistent sequence key %q", block.ID, string(k))
			}

			if block.PrevBlockHash != prevHash {
				res.FailedBlock = block.ID
				return fmt.Errorf("chain broken at block %s: expected prev_hash %s, got %s",
					block.ID, prevHash, block.PrevBlockHash)
			}

			expectedHash := calculateBlockHash(block)
			if block.BlockHash != expectedHash {
				res.FailedBlock = block.ID
				return fmt.Errorf("block %s hash mismatch: expected %s, got %s",
					block.ID, expectedHash, block.BlockHash)
			}

			prevHash = block.BlockHash
			res.HeadBlockID = block.ID
			res.HeadHash = block.BlockHash
		}
		return nil
	})

	if err != nil {
		res.Valid = false
		res.Message = err.Error()
		return res
	}

	res.Valid = true
	res.Message = "chain intact"
	return res
}

func lastBlockHash(b *bolt.Bucket) (string, error) {
	cursor := b.Cursor()
	k, v := cursor.Last()
	if k == nil {
		return genesisPrevHash, nil
	}

	var block models.Block
	if err := json.Unmarshal(v, &block); err != nil {
		return "", fmt.Errorf("last block is corrupt: %w", err)
	}
	return block.BlockHash, nil
}

// calculateBlockHash memasukkan field Quarantined ke dalam material hash sehingga
// setiap perubahan pada status karantina juga akan terdeteksi oleh VerifyChain.
func calculateBlockHash(block models.Block) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%t",
		block.ID,
		block.Timestamp.Format(time.RFC3339Nano),
		block.FilePath,
		block.Action,
		block.OldHash,
		block.NewHash,
		block.PrevBlockHash,
		block.Quarantined,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func containsIgnoreCase(s, substr string) bool {
	return len(substr) > 0 && strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func countKeys(b *bolt.Bucket) int {
	count := 0
	cursor := b.Cursor()
	for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
		count++
	}
	return count
}

// ---------------------------------------------------------------------------
// Metrics operations
// ---------------------------------------------------------------------------

// SaveMetric menyimpan satu titik data metrik scan cycle secara append-only.
func (l *Ledger) SaveMetric(m models.ScanMetric) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMetrics)
		if b == nil {
			return fmt.Errorf("metrics bucket missing")
		}
		data, err := json.Marshal(m)
		if err != nil {
			return err
		}
		// Key = timestamp unix-nano supaya ter-sort ascending secara natural.
		key := []byte(fmt.Sprintf("%019d", m.Timestamp.UnixNano()))
		if err := b.Put(key, data); err != nil {
			return err
		}

		// Retensi: hapus titik paling lama bila melewati batas.
		total := countKeys(b)
		limit := l.maxMetricEntries
		if limit <= 0 {
			return nil
		}
		if total <= limit {
			return nil
		}

		toDelete := make([][]byte, 0, total-limit)
		cursor := b.Cursor()
		for k, _ := cursor.First(); k != nil && len(toDelete) < total-limit; k, _ = cursor.Next() {
			toDelete = append(toDelete, append([]byte(nil), k...))
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetMetrics mengembalikan N titik metrik terbaru (paling baru di akhir).
// limit <= 0 berarti "ambil semua".
func (l *Ledger) GetMetrics(limit int) ([]models.ScanMetric, error) {
	metrics := make([]models.ScanMetric, 0, 64)

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMetrics)
		if b == nil {
			return nil
		}

		if limit <= 0 {
			return b.ForEach(func(k, v []byte) error {
				var m models.ScanMetric
				if err := json.Unmarshal(v, &m); err == nil {
					metrics = append(metrics, m)
				}
				return nil
			})
		}

		// Ambil `limit` entry terakhir (reverse), lalu balik agar ascending.
		cursor := b.Cursor()
		collected := make([]models.ScanMetric, 0, limit)
		for k, v := cursor.Last(); k != nil && len(collected) < limit; k, v = cursor.Prev() {
			var m models.ScanMetric
			if err := json.Unmarshal(v, &m); err == nil {
				collected = append(collected, m)
			}
		}
		// Reverse
		for i := len(collected) - 1; i >= 0; i-- {
			metrics = append(metrics, collected[i])
		}
		return nil
	})

	return metrics, err
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// LedgerExport adalah bentuk portable dari seluruh isi ledger untuk keperluan
// backup eksternal (Telegram dokumen / webhook / arsip skripsi).
type LedgerExport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	TotalBlocks int                 `json:"total_blocks"`
	HeadBlockID string              `json:"head_block_id,omitempty"`
	HeadHash    string              `json:"head_hash"`
	Blocks      []models.Block      `json:"blocks"`
	Verify      VerifyResult        `json:"verify"`
	Metrics     []models.ScanMetric `json:"metrics,omitempty"`
}

// ExportAll mengekspor seluruh blok + verifikasi rantai + metrik terakhir.
func (l *Ledger) ExportAll(includeMetrics bool) (*LedgerExport, error) {
	exp := &LedgerExport{
		GeneratedAt: time.Now().UTC(),
		Blocks:      []models.Block{},
	}

	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}
		exp.TotalBlocks = countKeys(b)

		return b.ForEach(func(k, v []byte) error {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				return nil
			}
			exp.Blocks = append(exp.Blocks, block)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	exp.Verify = l.VerifyChain()
	exp.HeadBlockID = exp.Verify.HeadBlockID
	exp.HeadHash = exp.Verify.HeadHash

	if includeMetrics {
		m, err := l.GetMetrics(500) // batasi 500 titik terakhir
		if err == nil {
			exp.Metrics = m
		}
	}

	return exp, nil
}
