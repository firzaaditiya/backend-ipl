package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/skripsi/fim-ipl/internal/fsx"
	"github.com/skripsi/fim-ipl/internal/models"
)

type Scanner struct {
	workerCount     int
	watchPaths      []string
	mu              sync.RWMutex
	isRunning       bool
	isScanning      bool
	maintenanceMode bool
	stopChan        chan struct{}
	intervalCh      chan int
	wg              sync.WaitGroup
	scanCycleFn     func()
}

const (
	defaultWorkerCount = 4
	minIntervalSec     = 30
	maxIntervalSec     = 86400
)

func New(workerCount int, watchPaths []string) *Scanner {
	if workerCount <= 0 {
		workerCount = defaultWorkerCount
	}
	return &Scanner{
		workerCount: workerCount,
		watchPaths:  watchPaths,
		stopChan:    make(chan struct{}),
		intervalCh:  make(chan int, 1),
	}
}

// SetMaintenanceMode mengaktifkan/menonaktifkan mode maintenance.
// Ketika aktif, seluruh scan cycle akan di-skip sehingga tidak menghasilkan
// false-positive saat admin melakukan update WordPress / install plugin.
func (s *Scanner) SetMaintenanceMode(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maintenanceMode = on
}

// IsMaintenance mengembalikan status maintenance mode saat ini.
func (s *Scanner) IsMaintenance() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maintenanceMode
}

func HashFile(path string) (string, error) {
	// O_NOFOLLOW (Linux): symlink ditolak saat open, bukan hanya saat
	// Lstat — menutup jendela TOCTOU antara Walk dan hashing, ketika
	// penyerang bisa menukar file biasa menjadi symlink ke target di luar
	// watch path. Di platform lain, open biasa (lihat internal/fsx).
	f, err := fsx.OpenReadNoFollow(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, 32*1024)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

const maxScanFileSize = 50 * 1024 * 1024

// ErrFileOversize menandai file non-kode yang dilewati karena melebihi
// batas pindai. File seperti ini TIDAK di-hash, tetapi juga TIDAK boleh
// dilaporkan DELETED bila sebelumnya ada di baseline (lihat
// CompareWithBaseline): file-nya masih ada, hanya tidak diperiksa isinya.
// Batasan ini didokumentasikan di README sebagai keterbatasan yang diketahui.
var ErrFileOversize = errors.New("file melebihi batas pindai 50 MB (non-kode); tidak di-hash")

// collectFiles mengembalikan path file yang akan di-hash. File yang tidak
// dapat dibaca atau berupa symlink TIDAK diikuti; keduanya dikembalikan
// sebagai hasil ber-error agar bisa dilaporkan sebagai UNREADABLE, bukan
// dianggap DELETED.
func (s *Scanner) collectFiles() ([]string, []models.ScanResult, error) {
	s.mu.RLock()
	paths := make([]string, len(s.watchPaths))
	copy(paths, s.watchPaths)
	s.mu.RUnlock()

	var files []string
	var rejected []models.ScanResult

	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				// Error pada root harus menggagalkan siklus agar admin tahu
				// watch path hilang/tidak dapat diakses. Error pada entry lain
				// dicatat sebagai file tidak terbaca agar tidak hilang diam-diam.
				if filepath.Clean(path) == filepath.Clean(root) {
					return walkErr
				}
				rejected = append(rejected, models.ScanResult{
					Path: path,
					Err:  fmt.Errorf("tidak dapat diakses: %w", walkErr),
				})
				return nil
			}

			// filepath.Walk memakai Lstat. Symlink tidak boleh diikuti karena
			// HashFile akan membaca target di luar watch path dan karantina
			// hanya akan menolaknya. Laporkan sebagai temuan yang mencurigakan.
			if info.Mode()&os.ModeSymlink != 0 {
				target, _ := os.Readlink(path)
				reason := "symlink tidak dipindai (target di luar watch path)"
				if target != "" {
					reason = "symlink tidak dipindai menuju " + target
				}
				rejected = append(rejected, models.ScanResult{
					Path: path,
					Err:  errors.New(reason),
				})
				return nil
			}

			if info.IsDir() {
				return nil
			}
			// Batas ukuran mencegah file raksasa (video/backup) membebani I/O.
			// File kode tetap dipindai berapa pun ukurannya karena merupakan
			// target utama webshell/backdoor. File non-kode yang melebihi
			// batas dikembalikan sebagai hasil ber-error ErrFileOversize
			// agar CompareWithBaseline tidak menganggapnya DELETED.
			if info.Size() > maxScanFileSize && !isCodeLike(path) {
				rejected = append(rejected, models.ScanResult{
					Path: path,
					// Izin tetap teramati walau isi tidak di-hash, agar
					// perubahan mode file oversize tetap bisa diadopsi
					// baseline atau dilaporkan pada siklus berikutnya.
					Mode: uint32(info.Mode().Perm()),
					Err:  fmt.Errorf("%w (%d byte)", ErrFileOversize, info.Size()),
				})
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}

	return files, rejected, nil
}

// isCodeLike menandai file yang dapat dieksekusi/diinterpretasikan web server.
// Dipakai untuk mengecualikan file kode dari batas ukuran.
func isCodeLike(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(name, ".htaccess") || strings.HasSuffix(name, ".user.ini") {
		return true
	}
	// Double extension lazim dipakai menyamarkan webshell (mis. shell.php.jpg).
	if strings.Contains(name, ".php.") ||
		strings.Contains(name, ".phtml.") ||
		strings.Contains(name, ".phar.") {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar",
		".inc", ".module", ".theme", ".ini", ".env", ".pl", ".py", ".cgi", ".sh":
		return true
	}
	return false
}

func (s *Scanner) Scan() ([]models.ScanResult, error) {
	s.mu.RLock()
	workerCount := s.workerCount
	s.mu.RUnlock()

	files, rejected, err := s.collectFiles()
	if err != nil {
		return nil, err
	}

	if len(files) == 0 && len(rejected) == 0 {
		return nil, nil
	}

	jobs := make(chan string, len(files))
	results := make(chan models.ScanResult, len(files)+len(rejected))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go s.worker(jobs, results, &wg)
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var scanResults []models.ScanResult
	scanResults = append(scanResults, rejected...)
	for result := range results {
		scanResults = append(scanResults, result)
	}

	return scanResults, nil
}

func (s *Scanner) worker(jobs <-chan string, results chan<- models.ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range jobs {
		func() {
			// HashFile membaca file yang bisa berubah/hilang kapan saja.
			// Panic pada satu file tidak boleh menghentikan seluruh worker.
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[Scanner] panic while hashing %s: %v", path, rec)
					results <- models.ScanResult{Path: path, Err: fmt.Errorf("panic: %v", rec)}
				}
			}()

			// Lstat (bukan Stat): symlink ditolak di sini, sebelum HashFile.
			// Mode dicatat dari Lstat agar perubahan izin terdeteksi walau
			// hashing gagal (mis. file mode 0600 milik www-data).
			info, err := os.Lstat(path)
			if err != nil {
				results <- models.ScanResult{Path: path, Err: err}
				return
			}
			mode := uint32(info.Mode().Perm())
			if info.Mode()&os.ModeSymlink != 0 {
				results <- models.ScanResult{
					Path: path,
					Mode: mode,
					Err:  errors.New("symlink tidak dipindai (target di luar watch path)"),
				}
				return
			}

			hash, err := HashFile(path)
			if err != nil {
				results <- models.ScanResult{Path: path, Mode: mode, Err: err}
				return
			}

			results <- models.ScanResult{
				Path:    path,
				Hash:    hash,
				Mode:    mode,
				Size:    info.Size(),
				ModTime: info.ModTime(),
			}
		}()
	}
}

// WorkerCount mengembalikan jumlah worker hashing yang dikonfigurasi.
// Dipakai main.go agar paralelisme perbandingan baseline memakai nilai yang
// sama (sebelum v1.4.0, CompareWithBaseline memakai 4 goroutine secara
// hardcode dan mengabaikan konfigurasi ini).
func (s *Scanner) WorkerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.workerCount
}

func (s *Scanner) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

// TryStartScan mencoba memulai scan. Return false jika scan sebelumnya masih berjalan.
func (s *Scanner) TryStartScan() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isScanning {
		return false
	}
	s.isScanning = true
	return true
}

// FinishScan menandai scan cycle selesai
func (s *Scanner) FinishScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isScanning = false
}

func (s *Scanner) StartMonitoring(intervalSec int) {
	// Interval di bawah minimum dijepit ke minimum (30 detik), bukan ke
	// default 300 detik: diam-diam memakai 300 saat admin meminta 30
	// adalah perilaku yang menyesatkan (diperbaiki di v1.4.0).
	if intervalSec < minIntervalSec {
		intervalSec = minIntervalSec
	}
	if intervalSec > maxIntervalSec {
		intervalSec = maxIntervalSec
	}

	s.mu.Lock()
	if s.isRunning {
		s.mu.Unlock()
		return
	}
	s.isRunning = true
	stopCh := make(chan struct{})
	s.stopChan = stopCh
	cycleFn := s.scanCycleFn
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
		defer ticker.Stop()

		if cycleFn != nil {
			cycleFn()
		}

		for {
			select {
			case <-ticker.C:
				s.mu.RLock()
				fn := s.scanCycleFn
				s.mu.RUnlock()
				if fn != nil {
					fn()
				}
			case next := <-s.intervalCh:
				if next >= minIntervalSec && next <= maxIntervalSec {
					ticker.Reset(time.Duration(next) * time.Second)
					log.Printf("[Scanner] Scan interval changed to %ds", next)
				}
			case <-stopCh:
				return
			}
		}
	}()
}

// StopMonitoring menghentikan ticker dan menunggu goroutine scan selesai.
// Penting agar database tidak ditutup saat masih ada scan yang menulis.
func (s *Scanner) StopMonitoring() {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return
	}
	close(s.stopChan)
	s.isRunning = false
	s.mu.Unlock()

	s.wg.Wait()
}

func (s *Scanner) RegisterScanCycle(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanCycleFn = fn
}

// UpdateConfig menerapkan perubahan worker, watch path, dan interval tanpa
// restart daemon. Interval baru langsung dipakai ticker yang sedang berjalan.
func (s *Scanner) UpdateConfig(workerCount int, watchPaths []string, intervalSec int) {
	s.mu.Lock()
	if workerCount > 0 {
		s.workerCount = workerCount
	}
	if len(watchPaths) > 0 {
		s.watchPaths = watchPaths
	}
	running := s.isRunning
	s.mu.Unlock()

	if running && intervalSec >= minIntervalSec && intervalSec <= maxIntervalSec {
		select {
		case s.intervalCh <- intervalSec:
		default:
			// Buang nilai lama lalu kirim yang terbaru.
			select {
			case <-s.intervalCh:
			default:
			}
			select {
			case s.intervalCh <- intervalSec:
			default:
			}
		}
	}
}
