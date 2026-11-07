package scanner

import (
	"errors"
	"log"
	"sort"
	"sync"

	"github.com/skripsi/fim-ipl/internal/models"
)

type CompareResult struct {
	Modified   []models.AnomalyEvent
	Created    []models.AnomalyEvent
	Deleted    []models.AnomalyEvent
	Unreadable []models.AnomalyEvent
	// ModeChanged mencatat perubahan izin (chmod) yang isinya tidak berubah.
	ModeChanged []models.AnomalyEvent
	// ModeAdoptions adalah path baseline lama (Mode == 0, dari sebelum
	// v1.5.0) yang modenya teramati pada siklus ini. Caller wajib menulis
	// adopsi ini ke baseline (AdoptBaselineModes) agar perubahan izin
	// pada siklus berikutnya benar-benar terdeteksi, tanpa menimbulkan
	// event palsu pada siklus pertama setelah upgrade.
	ModeAdoptions map[string]uint32
	// SkippedOversize menghitung file non-kode >50 MB yang dilewati pada
	// siklus ini (isinya tidak diperiksa).
	SkippedOversize int
	// ExcludedFiles menghitung berkas yang dikecualikan dari deteksi pada
	// siklus ini (exclude_globs atau kebijakan uploads, T-05). Berkas ini
	// tetap masuk baseline — yang tidak terjadi hanyalah event dan
	// karantina — sehingga angkanya harus terlihat di metrik dan dasbor
	// agar pengecualian tidak menjadi blind spot diam-diam.
	ExcludedFiles int
	// Excluded adalah daftar path yang dikecualikan pada siklus ini
	// (terurut, deterministik). Caller memakainya untuk memasukkan berkas
	// tersebut ke baseline tanpa event, agar baseline tetap mencerminkan
	// keadaan disk dan tercakup digest (lihat main.go).
	Excluded []string
}

// CompareWithBaseline membandingkan hasil scan dengan baseline. workers
// adalah jumlah goroutine pembanding (<= 0 berarti default 4); nilai ini
// berasal dari konfigurasi scanner agar konsisten dengan worker hashing.
// exclusions (nil = tidak ada) adalah aturan pengecualian T-05: path yang
// dikecualikan tidak menghasilkan event apa pun, tetapi tetap dihitung di
// ExcludedFiles dan modenya tetap diadopsi bila baseline lama belum
// mencatatnya.
//
// Perbandingan memakai hash DAN mode (izin berkas). Perubahan mode saja —
// mis. chmod 777 pada file konfigurasi — menghasilkan MODE_CHANGED; hash
// yang sama dengan mode yang sama berarti tidak ada temuan. Baseline lama
// yang belum mencatat mode (Mode == 0) tidak menghasilkan event pada
// siklus pertama: modenya diadopsi diam-diam lewat ModeAdoptions.
func CompareWithBaseline(scanResults []models.ScanResult, baseline map[string]models.FileRecord, workers int, exclusions *Exclusions) *CompareResult {
	if workers <= 0 {
		workers = 4
	}
	result := &CompareResult{ModeAdoptions: make(map[string]uint32)}
	var mu sync.Mutex
	excluded := make(map[string]struct{})
	markExcluded := func(path string) {
		mu.Lock()
		excluded[path] = struct{}{}
		mu.Unlock()
	}

	scannedMap := make(map[string]models.ScanResult, len(scanResults))
	errorMap := make(map[string]models.ScanResult)
	skippedMap := make(map[string]models.ScanResult)
	for _, sr := range scanResults {
		if sr.Err != nil {
			// File yang dilewati karena batas ukuran tetap ada di disk:
			// jangan laporkan sebagai DELETED maupun UNREADABLE.
			if errors.Is(sr.Err, ErrFileOversize) {
				skippedMap[sr.Path] = sr
				continue
			}
			errorMap[sr.Path] = sr
			continue
		}
		scannedMap[sr.Path] = sr
	}

	var wg sync.WaitGroup
	baselineChan := make(chan models.FileRecord, 100)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for record := range baselineChan {
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							log.Printf("[Scanner] panic while comparing %s: %v", record.Path, rec)
						}
					}()
					scanned, exists := scannedMap[record.Path]
					// Pengecualian (T-05): tidak ada event apa pun untuk
					// path ini — tetapi hitung dan adopsi modenya bila
					// baseline lama belum mencatatnya, agar baseline
					// tetap lengkap.
					if exclusions != nil && exclusions.IsExcluded(record.Path) {
						markExcluded(record.Path)
						if record.Mode == 0 {
							if mode := modeObservedFor(record.Path, scanned, exists, skippedMap, errorMap); mode != 0 {
								mu.Lock()
								result.ModeAdoptions[record.Path] = mode
								mu.Unlock()
							}
						}
						return
					}
					if !exists {
						if skipped, isSkipped := skippedMap[record.Path]; isSkipped {
							// File ada tetapi tidak di-hash karena batas
							// ukuran: bukan DELETED, bukan UNREADABLE.
							// Izinnya tetap teramati, jadi adopsi mode
							// untuk baseline lama tetap bisa dilakukan.
							if record.Mode == 0 && skipped.Mode != 0 {
								mu.Lock()
								result.ModeAdoptions[record.Path] = skipped.Mode
								mu.Unlock()
							}
							return
						}
						if failed, unreadable := errorMap[record.Path]; unreadable {
							// Jangan pernah menganggap file yang gagal dibaca
							// sebagai DELETED: itu akan menghapus baseline dan
							// menciptakan blind spot permanen.
							mu.Lock()
							result.Unreadable = append(result.Unreadable, models.AnomalyEvent{
								FilePath: record.Path,
								Action:   models.ActionUnreadable,
								OldHash:  record.Hash,
								OldMode:  record.Mode,
								NewMode:  failed.Mode,
								ScanErr:  failed.Err.Error(),
							})
							mu.Unlock()
						} else {
							mu.Lock()
							result.Deleted = append(result.Deleted, models.AnomalyEvent{
								FilePath: record.Path,
								Action:   models.ActionDeleted,
								OldHash:  record.Hash,
								OldMode:  record.Mode,
								NewHash:  "",
							})
							mu.Unlock()
						}
					} else if scanned.Hash != record.Hash {
						mu.Lock()
						result.Modified = append(result.Modified, models.AnomalyEvent{
							FilePath: record.Path,
							Action:   models.ActionModified,
							OldHash:  record.Hash,
							NewHash:  scanned.Hash,
							OldMode:  record.Mode,
							NewMode:  scanned.Mode,
						})
						mu.Unlock()
					} else if record.Mode == 0 {
						// Baseline dari sebelum v1.5.0 belum mencatat mode.
						// Adopsi mode yang teramati tanpa event agar 3901
						// file lama tidak sekaligus dilaporkan berubah.
						if scanned.Mode != 0 {
							mu.Lock()
							result.ModeAdoptions[record.Path] = scanned.Mode
							mu.Unlock()
						}
					} else if scanned.Mode != record.Mode {
						// Isi sama, izin berubah: tetap anomali integritas.
						// OldHash == NewHash karena hash tidak berubah.
						mu.Lock()
						result.ModeChanged = append(result.ModeChanged, models.AnomalyEvent{
							FilePath: record.Path,
							Action:   models.ActionModeChanged,
							OldHash:  scanned.Hash,
							NewHash:  scanned.Hash,
							OldMode:  record.Mode,
							NewMode:  scanned.Mode,
						})
						mu.Unlock()
					}
				}()
			}
		}()
	}

	for _, record := range baseline {
		baselineChan <- record
	}
	close(baselineChan)
	wg.Wait()

	for path, sr := range scannedMap {
		if _, exists := baseline[path]; !exists {
			if exclusions != nil && exclusions.IsExcluded(path) {
				markExcluded(path)
				continue
			}
			result.Created = append(result.Created, models.AnomalyEvent{
				FilePath: path,
				Action:   models.ActionCreated,
				OldHash:  "",
				NewHash:  sr.Hash,
				NewMode:  sr.Mode,
			})
		}
	}

	// File yang tidak dapat dibaca tetapi belum pernah ada di baseline juga
	// harus dilaporkan. Tanpa ini, backdoor dengan izin 000/symlink baru tidak
	// akan pernah masuk ledger.
	for path, sr := range errorMap {
		if _, exists := baseline[path]; exists {
			continue
		}
		if exclusions != nil && exclusions.IsExcluded(path) {
			markExcluded(path)
			continue
		}
		result.Unreadable = append(result.Unreadable, models.AnomalyEvent{
			FilePath: path,
			Action:   models.ActionUnreadable,
			NewMode:  sr.Mode,
			ScanErr:  sr.Err.Error(),
		})
	}

	result.SkippedOversize = len(skippedMap)
	result.ExcludedFiles = len(excluded)
	for path := range excluded {
		result.Excluded = append(result.Excluded, path)
	}
	sort.Strings(result.Excluded)

	// Urutkan secara deterministik: ledger dan laporan menjadi reprodusibel.
	sort.Slice(result.Modified, func(i, j int) bool {
		return result.Modified[i].FilePath < result.Modified[j].FilePath
	})
	sort.Slice(result.Created, func(i, j int) bool {
		return result.Created[i].FilePath < result.Created[j].FilePath
	})
	sort.Slice(result.Deleted, func(i, j int) bool {
		return result.Deleted[i].FilePath < result.Deleted[j].FilePath
	})
	sort.Slice(result.ModeChanged, func(i, j int) bool {
		return result.ModeChanged[i].FilePath < result.ModeChanged[j].FilePath
	})
	sort.Slice(result.Unreadable, func(i, j int) bool {
		return result.Unreadable[i].FilePath < result.Unreadable[j].FilePath
	})

	log.Printf("[Scanner] Comparison done: %d modified, %d created, %d mode-changed, %d deleted, %d unreadable, %d skipped (oversize), %d excluded",
		len(result.Modified), len(result.Created), len(result.ModeChanged), len(result.Deleted), len(result.Unreadable), result.SkippedOversize, result.ExcludedFiles)

	return result
}

// modeObservedFor mengembalikan mode yang teramati untuk satu path dari
// hasil scan (dipakai adopsi mode baseline lama pada path yang
// dikecualikan — T-05). 0 berarti tidak ada mode yang teramati.
func modeObservedFor(path string, scanned models.ScanResult, scannedOK bool, skippedMap, errorMap map[string]models.ScanResult) uint32 {
	if scannedOK && scanned.Mode != 0 {
		return scanned.Mode
	}
	if skipped, ok := skippedMap[path]; ok {
		return skipped.Mode
	}
	if failed, ok := errorMap[path]; ok {
		return failed.Mode
	}
	return 0
}

func (cr *CompareResult) TotalAnomalies() int {
	return len(cr.Modified) + len(cr.Created) + len(cr.ModeChanged) + len(cr.Deleted) + len(cr.Unreadable)
}

func (cr *CompareResult) AllEvents() []models.AnomalyEvent {
	events := make([]models.AnomalyEvent, 0, cr.TotalAnomalies())
	events = append(events, cr.Modified...)
	events = append(events, cr.Created...)
	events = append(events, cr.ModeChanged...)
	events = append(events, cr.Unreadable...)
	events = append(events, cr.Deleted...)
	return events
}
