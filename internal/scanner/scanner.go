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

	"github.com/skripsi/fim-ipl/internal/models"
)

type Scanner struct {
	workerCount     int
	watchPaths      []string
	intervalSec     int
	mu              sync.RWMutex
	isRunning       bool
	isScanning      bool
	maintenanceMode bool
	stopChan        chan struct{}
	intervalCh      chan int
	wg              sync.WaitGroup
	scanCycleFn     func()
	OnAnomaly       func(event models.AnomalyEvent)
}

const (
	defaultWorkerCount = 4
	defaultIntervalSec = 300
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
		intervalSec: defaultIntervalSec,
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
	f, err := os.Open(path)
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

// CollectFiles mengembalikan path file yang akan di-hash. File yang tidak
// dapat dibaca atau berupa symlink TIDAK diikuti; keduanya dikembalikan oleh
// collectFiles sebagai hasil ber-error agar bisa dilaporkan sebagai
// UNREADABLE, bukan dianggap DELETED.
func (s *Scanner) CollectFiles() ([]string, error) {
	files, _, err := s.collectFiles()
	return files, err
}

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
			// target utama webshell/backdoor.
			if info.Size() > maxScanFileSize && !isCodeLike(path) {
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

			info, err := os.Stat(path)
			if err != nil {
				results <- models.ScanResult{Path: path, Err: err}
				return
			}

			hash, err := HashFile(path)
			if err != nil {
				results <- models.ScanResult{Path: path, Err: err}
				return
			}

			results <- models.ScanResult{
				Path:    path,
				Hash:    hash,
				Size:    info.Size(),
				ModTime: info.ModTime(),
			}
		}()
	}
}

func (s *Scanner) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRunning
}

// IsScanning mengembalikan true jika ada siklus scan (manual/ticker) yang
// sedang berjalan.
func (s *Scanner) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isScanning
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
	if intervalSec < minIntervalSec {
		intervalSec = defaultIntervalSec
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
	s.intervalSec = intervalSec
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
	if intervalSec >= minIntervalSec && intervalSec <= maxIntervalSec {
		s.intervalSec = intervalSec
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
