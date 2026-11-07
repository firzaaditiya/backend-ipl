package ledger

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketBlocks          = []byte("blocks")
	bucketBaseline        = []byte("baseline")
	bucketMeta            = []byte("meta")
	bucketMetrics         = []byte("metrics")
	bucketQuarantineModes = []byte("quarantine_modes")
	// bucketRevokedTokens menyimpan jti token yang dicabut lewat logout
	// (nilai = unix expiry token). Bukan bagian hash-chain: ini status
	// sesi, bukan jejak audit. Entri kedaluwarsa dibersihkan saat ada
	// pencabutan baru (lihat RevokeToken).
	bucketRevokedTokens = []byte("revoked_tokens")
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
		for _, b := range [][]byte{bucketBlocks, bucketBaseline, bucketMeta, bucketMetrics, bucketQuarantineModes, bucketRevokedTokens} {
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

// ---------------------------------------------------------------------------
// Digest baseline (T-04, v1.6.0)
// ---------------------------------------------------------------------------
//
// Baseline hidup di bucket Bbolt yang TIDAK masuk hash-chain: root yang
// mengedit satu entri baseline secara langsung tidak merusak rantai.
// Digest menutup celah itu: setiap blok BASELINE_INIT/BASELINE_UPDATE
// membawa SHA-256 atas seluruh isi baseline pada saat itu (ikut dihitung
// ke dalam hash blok v3), sehingga perubahan diam-diam pada baseline
// terdeteksi dengan membandingkan digest blok terakhir dengan digest
// baseline saat ini (lihat VerifyBaselineDigest).

// baselineDigestFor menghitung SHA-256 atas isi baseline dalam format
// kanonis: satu baris per berkas, "path|hash|mode|size\n" (mode dan size
// dalam desimal), diurutkan berdasarkan path. Format ini didokumentasikan
// agar verifier mandiri (T-06, cmd/verify) dapat menghitung ulang digest
// yang sama dari ekspor JSON.
func baselineDigestFor(records map[string]models.FileRecord) (string, int) {
	paths := make([]string, 0, len(records))
	for path := range records {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var sb strings.Builder
	for _, path := range paths {
		r := records[path]
		fmt.Fprintf(&sb, "%s|%s|%d|%d\n", path, r.Hash, r.Mode, r.Size)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:]), len(paths)
}

// BaselineDigest menghitung digest baseline saat ini.
func (l *Ledger) BaselineDigest() (string, int, error) {
	records, err := l.GetBaseline()
	if err != nil {
		return "", 0, err
	}
	digest, count := baselineDigestFor(records)
	return digest, count, nil
}

// LatestBaselineBlock mengembalikan blok BASELINE_INIT/BASELINE_UPDATE
// terbaru (nil bila baseline belum pernah dibuat).
func (l *Ledger) LatestBaselineBlock() (*models.Block, error) {
	var found *models.Block
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
			if block.Action == models.ActionBaselineInit || block.Action == models.ActionBaselineUpdate {
				found = &block
				return nil
			}
		}
		return nil
	})
	return found, err
}

// BaselineVerification adalah hasil perbandingan digest blok baseline
// terakhir dengan digest baseline saat ini.
type BaselineVerification struct {
	Match          bool   `json:"match"`
	BlockID        string `json:"block_id"`
	ExpectedDigest string `json:"expected_digest"`
	ActualDigest   string `json:"actual_digest"`
	ExpectedCount  int    `json:"expected_count"`
	ActualCount    int    `json:"actual_count"`
	Message        string `json:"message"`
}

// VerifyBaselineDigest membandingkan digest pada blok baseline terakhir
// dengan digest baseline saat ini. Ketidakcocokan berarti ada entri
// baseline yang berubah di luar jalur resmi (edit langsung di Bbolt,
// atau rebuild yang tidak tercatat). Verifikasi ini TIDAK memeriksa
// hash-chain — itu tugas VerifyChain; keduanya saling melengkapi.
func (l *Ledger) VerifyBaselineDigest() (BaselineVerification, error) {
	block, err := l.LatestBaselineBlock()
	if err != nil {
		return BaselineVerification{}, err
	}
	actualDigest, actualCount, err := l.BaselineDigest()
	if err != nil {
		return BaselineVerification{}, err
	}
	if block == nil {
		return BaselineVerification{
			Match:        false,
			ActualDigest: actualDigest,
			ActualCount:  actualCount,
			Message:      "belum ada blok baseline: baseline belum pernah dibuat",
		}, nil
	}
	if block.BaselineDigest == "" {
		return BaselineVerification{
			Match:         false,
			BlockID:       block.ID,
			ActualDigest:  actualDigest,
			ActualCount:   actualCount,
			ExpectedCount: block.BaselineCount,
			Message:       "blok baseline terakhir tidak membawa digest (dibuat sebelum v1.6.0)",
		}, nil
	}
	if block.BaselineDigest == actualDigest && block.BaselineCount == actualCount {
		return BaselineVerification{
			Match:          true,
			BlockID:        block.ID,
			ExpectedDigest: block.BaselineDigest,
			ActualDigest:   actualDigest,
			ExpectedCount:  block.BaselineCount,
			ActualCount:    actualCount,
			Message:        "baseline cocok dengan blok baseline terakhir",
		}, nil
	}
	return BaselineVerification{
		Match:          false,
		BlockID:        block.ID,
		ExpectedDigest: block.BaselineDigest,
		ActualDigest:   actualDigest,
		ExpectedCount:  block.BaselineCount,
		ActualCount:    actualCount,
		Message:        "baseline BERBEDA dari blok baseline terakhir: ada entri yang berubah di luar jalur resmi",
	}, nil
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

// AdoptBaselineModes menulis mode yang teramati ke entri baseline yang
// belum mencatat mode (Mode == 0, dari sebelum v1.5.0), dalam satu
// transaksi. Hanya entri dengan Mode 0 yang disentuh; entri yang sudah
// punya mode tidak pernah ditimpa diam-diam oleh fungsi ini.
func (l *Ledger) AdoptBaselineModes(modes map[string]uint32) error {
	if len(modes) == 0 {
		return nil
	}
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBaseline)
		if b == nil {
			return nil
		}
		for path, mode := range modes {
			if mode == 0 {
				continue
			}
			v := b.Get([]byte(path))
			if v == nil {
				continue
			}
			var record models.FileRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			if record.Mode != 0 {
				continue
			}
			record.Mode = mode
			data, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(path), data); err != nil {
				return err
			}
		}
		return nil
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

// ---------------------------------------------------------------------------
// Quarantine original modes
// ---------------------------------------------------------------------------
//
// Saat file dikarantina (chmod 000), permission aslinya dicatat di bucket
// ini agar Release bisa mengembalikannya persis seperti semula, bukan ke
// nilai default 0644. Bucket ini BUKAN bagian dari hash-chain (isinya
// status operasional, bukan jejak audit), sehingga penambahannya tidak
// mengubah verifikasi blok-blok lama. Entri dihapus saat file dirilis;
// bila entri tidak ditemukan (file dikarantina sebelum v1.1.0), Release
// memakai fallback 0644.

// RecordQuarantineMode menyimpan permission asli file yang dikarantina.
func (l *Ledger) RecordQuarantineMode(path string, mode uint32) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQuarantineModes)
		if b == nil {
			return nil
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], mode)
		return b.Put([]byte(path), buf[:])
	})
}

// GetQuarantineMode mengembalikan permission asli file yang sedang
// dikarantina — yaitu permission yang akan dipulihkan saat Release.
// found=false berarti tidak ada catatan (file lama atau tidak pernah
// dikarantina lewat v1.1.0).
//
// Sejak v1.6.0 (T-04), sumber utamanya adalah RANTAI: mode pada blok
// karantina terakhir untuk path itu (NewMode; OldMode bila NewMode
// kosong). Mode pada blok v2/v3 ikut terlindungi hash, sehingga
// pengeditan diam-diam pada bucket quarantine_modes (yang mutable dan
// di luar rantai) tidak lagi bisa mengubah mode pemulihan. Bucket hanya
// dipakai sebagai fallback untuk karantina lama yang bloknya tidak
// membawa mode (mis. blok v1.0 tanpa OldMode/NewMode).
func (l *Ledger) GetQuarantineMode(path string) (uint32, bool, error) {
	if mode, found, err := l.getQuarantineModeFromChain(path); err == nil && found {
		return mode, true, nil
	}
	var (
		mode  uint32
		found bool
	)
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQuarantineModes)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(path))
		if v == nil || len(v) != 4 {
			return nil
		}
		mode = binary.BigEndian.Uint32(v)
		found = true
		return nil
	})
	return mode, found, err
}

// getQuarantineModeFromChain mencari blok karantina terakhir untuk satu
// path (paling baru dulu) dan mengembalikan modenya. Blok yang
// dipertimbangkan adalah blok dengan Quarantined=true; blok RELEASED dan
// DELETED tidak pernah membawa Quarantined=true, jadi tidak terpilih.
func (l *Ledger) getQuarantineModeFromChain(path string) (uint32, bool, error) {
	var (
		mode  uint32
		found bool
	)
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
			if block.FilePath != path || !block.Quarantined {
				continue
			}
			switch {
			case block.NewMode != 0:
				mode = block.NewMode
				found = true
			case block.OldMode != 0:
				mode = block.OldMode
				found = true
			}
			return nil
		}
		return nil
	})
	return mode, found, err
}

// DeleteQuarantineMode menghapus catatan permission setelah file dirilis.
func (l *Ledger) DeleteQuarantineMode(path string) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQuarantineModes)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(path))
	})
}

// ---------------------------------------------------------------------------
// Revoked tokens (logout)
// ---------------------------------------------------------------------------
//
// Sejak v1.5.0, logout mencabut token itu saja (bukan semua sesi): jti
// token ditulis ke bucket ini dan ParseClaims menolaknya sampai token
// kedaluwarsa. Token lama tanpa jti (sebelum v1.5.0) tidak bisa dicabut
// satu-per-satu; ia tetap valid sampai kedaluwarsa 24 jam atau sampai
// kredensial diubah (epoch naik).

// RevokeToken mencatat jti sebagai dicabut sampai expiresAt. Entri yang
// sudah kedaluwarsa dibersihkan dalam transaksi yang sama agar bucket
// tidak tumbuh tanpa batas.
func (l *Ledger) RevokeToken(jti string, expiresAt time.Time) error {
	if jti == "" {
		return nil
	}
	now := time.Now().Unix()
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRevokedTokens)
		if b == nil {
			return nil
		}
		// Bersihkan entri kedaluwarsa (peluang murah: satu iterasi per logout).
		_ = b.ForEach(func(k, v []byte) error {
			if len(v) == 8 && int64(binary.BigEndian.Uint64(v)) <= now {
				return b.Delete(k)
			}
			return nil
		})
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(expiresAt.Unix()))
		return b.Put([]byte(jti), buf[:])
	})
}

// IsTokenRevoked melaporkan apakah jti pernah dicabut dan tokennya belum
// kedaluwarsa. Entri kedaluwarsa dianggap tidak dicabut (tokennya sudah
// mati sendiri) dan dibiarkan untuk dibersihkan RevokeToken berikutnya.
func (l *Ledger) IsTokenRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	revoked := false
	_ = l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRevokedTokens)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(jti))
		if v == nil || len(v) != 8 {
			return nil
		}
		if int64(binary.BigEndian.Uint64(v)) > time.Now().Unix() {
			revoked = true
		}
		return nil
	})
	return revoked
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
			ID:        fmt.Sprintf("BLK-%06d", seq),
			Timestamp: time.Now(),
			FilePath:  event.FilePath,
			Action:    event.Action,
			OldHash:   event.OldHash,
			NewHash:   event.NewHash,
			// OldMode/NewMode dan QuarantineErr ikut dihitung ke dalam
			// block hash pada blok v2 (lihat calculateBlockHashV2); pada
			// blok v1 keduanya hanya metadata tampilan.
			OldMode:       event.OldMode,
			NewMode:       event.NewMode,
			Quarantined:   event.Quarantined,
			QuarantineErr: event.QuarantineErr,
			Actor:         event.Actor,
			Detail:        event.Detail,
			// Digest baseline (T-04): hanya terisi pada blok
			// BASELINE_INIT/BASELINE_UPDATE; kosong untuk blok lain.
			BaselineDigest: event.BaselineDigest,
			BaselineCount:  event.BaselineCount,
			PrevBlockHash:  prevHash,
			// Blok baru selalu memakai formula terbaru (v3); blok v1/v2
			// yang sudah ada tetap terverifikasi lewat formula lamanya
			// (lihat calculateBlockHash).
			HashVersion: 3,
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

// QuarantinedFile adalah satu berkas yang status TERAKHIR-nya masih
// dikarantina, beserta izin aslinya bila tercatat (nil bila berkas
// dikarantina sebelum pencatatan izin ada, sejak v1.1.0).
// Dipakai endpoint daftar karantina (v1.3.0) agar operator tidak perlu
// memburu blok terakhir di Audit Trail untuk mengetahui apa saja yang
// sedang diisolasi dan izin apa yang akan dipulihkan saat pelepasan.
type QuarantinedFile struct {
	FilePath     string  `json:"file_path"`
	OriginalMode *uint32 `json:"original_mode"`
}

// QuarantinedFiles mengembalikan daftar berkas yang sedang dikarantina,
// terurut menurut path agar tampilannya stabil di dasbor.
func (l *Ledger) QuarantinedFiles() ([]QuarantinedFile, error) {
	paths, err := l.GetCurrentlyQuarantinedPaths()
	if err != nil {
		return nil, err
	}
	out := make([]QuarantinedFile, 0, len(paths))
	for path := range paths {
		entry := QuarantinedFile{FilePath: path}
		if mode, found, err := l.GetQuarantineMode(path); err == nil && found {
			m := mode
			entry.OriginalMode = &m
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FilePath < out[j].FilePath })
	return out, nil
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
//
// Definisi resmi angka dashboard (satu-satunya yang dipakai naskah):
//   - Anomalies = seluruh blok kecuali RELEASED (termasuk UNREADABLE dan
//     MODE_CHANGED), kumulatif sejak awal ledger.
//   - TotalBlocks = seluruh blok, termasuk RELEASED.
//   - TotalFiles = jumlah entri baseline; safe = TotalFiles - Quarantined.
//   - QuarantinedFiles = file yang status TERAKHIR-nya masih dikarantina.
//
// Metode GetAnomalyCount yang lama dihapus di v1.5.0 karena menduplikasi
// definisi ini dengan nama yang sama.
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

			if models.IsAnomalyAction(block.Action) {
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
//  3. Urutan dan ID blok konsisten (BLK-%06d berurutan)
//
// Verifikasi isinya didelegasikan ke VerifyBlocks (fungsi murni tanpa
// akses DB), agar verifier mandiri cmd/verify dapat memakai logika yang
// persis sama terhadap ekspor JSON. Yang diperiksa VerifyChain di sini
// hanyalah konsistensi kunci Bbolt dengan ID blok — sesuatu yang tidak
// bisa diungkap dari ekspor saja.
func (l *Ledger) VerifyChain() VerifyResult {
	blocks := make([]models.Block, 0, 64)
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var block models.Block
			if err := json.Unmarshal(v, &block); err != nil {
				return fmt.Errorf("invalid block data at key %s", string(k))
			}
			// Key harus berupa sequence dan cocok dengan ID blok.
			seq, err := strconv.Atoi(string(k))
			if err != nil || block.ID != fmt.Sprintf("BLK-%06d", seq) {
				return fmt.Errorf("block %s has inconsistent sequence key %q", block.ID, string(k))
			}
			blocks = append(blocks, block)
		}
		return nil
	})
	if err != nil {
		return VerifyResult{
			VerifiedAt: time.Now().UTC(),
			HeadHash:   genesisPrevHash,
			Valid:      false,
			Message:    err.Error(),
		}
	}
	return VerifyBlocks(blocks)
}

// VerifyBlocks memeriksa integritas rantai dari daftar blok yang
// diberikan (tanpa akses DB). Dipakai VerifyChain dan verifier mandiri
// cmd/verify — keduanya menjalankan logika yang persis sama, sehingga
// hasil verifikasi dari ekspor tidak bisa berbeda dari verifikasi
// langsung di server.
//
// BATAS YANG JUJUR (single-node ledger): fungsi ini TIDAK dapat
// mendeteksi pemotongan ekor (tail truncation) — menghapus blok-blok
// terakhir menghasilkan rantai yang lebih pendek tetapi tetap utuh.
// Yang mendeteksinya adalah perbandingan dengan jangkar eksternal
// (head hash di alert Telegram / caption backup, T-06): bila head hash
// di Telegram tidak sama dengan head hash rantai saat ini, ada blok
// yang hilang.
func VerifyBlocks(blocks []models.Block) VerifyResult {
	res := VerifyResult{
		VerifiedAt:  time.Now().UTC(),
		HeadHash:    genesisPrevHash,
		TotalBlocks: len(blocks),
	}
	if len(blocks) == 0 {
		res.Valid = true
		res.Message = "chain intact (empty)"
		return res
	}

	prevHash := genesisPrevHash
	for i, block := range blocks {
		// ID harus BLK-%06d berurutan sesuai posisi di rantai.
		wantID := fmt.Sprintf("BLK-%06d", i+1)
		if block.ID != wantID {
			res.FailedBlock = block.ID
			res.Valid = false
			res.Message = fmt.Sprintf("block %s has inconsistent sequence (expected %s)", block.ID, wantID)
			return res
		}

		// Versi formula yang tidak dikenal ditolak di sini, bukan
		// diam-diam diverifikasi dengan formula lama.
		if block.HashVersion != 0 && block.HashVersion != 2 && block.HashVersion != 3 {
			res.FailedBlock = block.ID
			res.Valid = false
			res.Message = fmt.Sprintf("block %s has unknown hash_version %d", block.ID, block.HashVersion)
			return res
		}

		if block.PrevBlockHash != prevHash {
			res.FailedBlock = block.ID
			res.Valid = false
			res.Message = fmt.Sprintf("chain broken at block %s: expected prev_hash %s, got %s",
				block.ID, prevHash, block.PrevBlockHash)
			return res
		}

		expectedHash := calculateBlockHash(block)
		if block.BlockHash != expectedHash {
			res.FailedBlock = block.ID
			res.Valid = false
			res.Message = fmt.Sprintf("block %s hash mismatch: expected %s, got %s",
				block.ID, expectedHash, block.BlockHash)
			return res
		}

		prevHash = block.BlockHash
		res.HeadBlockID = block.ID
		res.HeadHash = block.BlockHash
	}

	res.Valid = true
	res.Message = "chain intact"
	return res
}

// RecordVerification menyimpan hasil verifikasi terjadwal terakhir di
// bucket meta (T-06). Satu entri saja yang disimpan (kunci
// "last_verification") — riwayat verifikasi tidak diperlukan, yang
// penting adalah status terakhir yang bisa dibandingkan dengan jangkar
// eksternal.
func (l *Ledger) RecordVerification(v models.LastVerification) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if b == nil {
			return fmt.Errorf("meta bucket missing")
		}
		return b.Put([]byte("last_verification"), data)
	})
}

// GetLastVerification mengembalikan hasil verifikasi terjadwal terakhir,
// atau nil bila belum pernah ada verifikasi (mis. sebelum boot pertama
// dengan v1.6.0).
func (l *Ledger) GetLastVerification() (*models.LastVerification, error) {
	var v *models.LastVerification
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if b == nil {
			return nil
		}
		data := b.Get([]byte("last_verification"))
		if data == nil {
			return nil
		}
		var lv models.LastVerification
		if err := json.Unmarshal(data, &lv); err != nil {
			return err
		}
		v = &lv
		return nil
	})
	return v, err
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

// calculateBlockHash memilih formula berdasarkan HashVersion blok:
// 0 (field tidak ada) = v1, 2 = v2, 3 = v3. Versi tidak dikenal tidak
// punya hash yang cocok, sehingga VerifyChain gagal di blok itu.
// Setiap versi formula tidak pernah diubah setelah didefinisikan;
// kebutuhan baru (seperti digest baseline di v3) memakai versi baru.
func calculateBlockHash(block models.Block) string {
	switch block.HashVersion {
	case 3:
		return calculateBlockHashV3(block)
	case 2:
		return calculateBlockHashV2(block)
	case 0:
		return calculateBlockHashV1(block)
	default:
		return ""
	}
}

// calculateBlockHashV1 adalah formula lama (v1.0–v1.5.0), dipertahankan
// tanpa perubahan agar 29 blok produksi yang sudah ada tetap
// terverifikasi. Formula ini hanya melindungi
// ID|Timestamp|FilePath|Action|OldHash|NewHash|PrevBlockHash|Quarantined,
// dan pemisah "|" tidak di-escape: dua tuple field yang berbeda bisa
// menghasilkan string yang sama bila path/aksi mengandung "|".
func calculateBlockHashV1(block models.Block) string {
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

// calculateBlockHashV2 (v1.6.0, T-02) melindungi SELURUH field kejadian:
// ID, Timestamp, FilePath, Action, OldHash, NewHash, OldMode, NewMode,
// Quarantined, QuarantineErr, Actor, Detail, PrevBlockHash, dan
// HashVersion sendiri. Pada v1, perubahan MODE_CHANGED tidak terlindungi
// karena OldHash == NewHash dan mode tidak masuk material hash — kini
// mengubah mode (atau alasan karantina, atau pelaku) tanpa memperbarui
// hash akan gagal tepat di blok itu.
//
// Encoding-nya length-prefixed ("panjang:nilai" per field, urutan
// tetap), sehingga batas field tidak pernah ambigu: path yang mengandung
// "|" atau ":" tidak bisa dipalsukan menjadi field lain, tidak seperti
// pemisah "|" pada v1.
func calculateBlockHashV2(block models.Block) string {
	var sb strings.Builder
	writeField := func(s string) {
		fmt.Fprintf(&sb, "%d:%s", len(s), s)
	}
	writeField(strconv.Itoa(block.HashVersion))
	writeField(block.ID)
	writeField(block.Timestamp.Format(time.RFC3339Nano))
	writeField(block.FilePath)
	writeField(block.Action)
	writeField(block.OldHash)
	writeField(block.NewHash)
	writeField(strconv.FormatUint(uint64(block.OldMode), 10))
	writeField(strconv.FormatUint(uint64(block.NewMode), 10))
	writeField(strconv.FormatBool(block.Quarantined))
	writeField(block.QuarantineErr)
	writeField(block.Actor)
	writeField(block.Detail)
	writeField(block.PrevBlockHash)
	hash := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}

// calculateBlockHashV3 (v1.6.0, T-04) = v2 ditambah BaselineDigest dan
// BaselineCount di akhir material hash, dengan urutan field yang sama.
// Blok baseline (BASELINE_INIT/BASELINE_UPDATE) kini membawa digest isi
// baseline yang ikut terlindungi hash, sehingga digest itu sendiri tidak
// bisa diubah tanpa merusak rantai. Blok non-baseline memakai digest
// kosong ("0:") dan count 0, jadi tidak ada ambiguitas.
func calculateBlockHashV3(block models.Block) string {
	var sb strings.Builder
	writeField := func(s string) {
		fmt.Fprintf(&sb, "%d:%s", len(s), s)
	}
	writeField(strconv.Itoa(block.HashVersion))
	writeField(block.ID)
	writeField(block.Timestamp.Format(time.RFC3339Nano))
	writeField(block.FilePath)
	writeField(block.Action)
	writeField(block.OldHash)
	writeField(block.NewHash)
	writeField(strconv.FormatUint(uint64(block.OldMode), 10))
	writeField(strconv.FormatUint(uint64(block.NewMode), 10))
	writeField(strconv.FormatBool(block.Quarantined))
	writeField(block.QuarantineErr)
	writeField(block.Actor)
	writeField(block.Detail)
	writeField(block.BaselineDigest)
	writeField(strconv.Itoa(block.BaselineCount))
	writeField(block.PrevBlockHash)
	hash := sha256.Sum256([]byte(sb.String()))
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
