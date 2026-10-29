package scanner

import (
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
}

func CompareWithBaseline(scanResults []models.ScanResult, baseline map[string]models.FileRecord) *CompareResult {
	result := &CompareResult{}
	var mu sync.Mutex

	scannedMap := make(map[string]models.ScanResult, len(scanResults))
	errorMap := make(map[string]models.ScanResult)
	for _, sr := range scanResults {
		if sr.Err != nil {
			errorMap[sr.Path] = sr
			continue
		}
		scannedMap[sr.Path] = sr
	}

	var wg sync.WaitGroup
	baselineChan := make(chan models.FileRecord, 100)

	for i := 0; i < 4; i++ {
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
					if !exists {
						if failed, unreadable := errorMap[record.Path]; unreadable {
							// Jangan pernah menganggap file yang gagal dibaca
							// sebagai DELETED: itu akan menghapus baseline dan
							// menciptakan blind spot permanen.
							mu.Lock()
							result.Unreadable = append(result.Unreadable, models.AnomalyEvent{
								FilePath: record.Path,
								Action:   models.ActionUnreadable,
								OldHash:  record.Hash,
								ScanErr:  failed.Err.Error(),
							})
							mu.Unlock()
						} else {
							mu.Lock()
							result.Deleted = append(result.Deleted, models.AnomalyEvent{
								FilePath: record.Path,
								Action:   models.ActionDeleted,
								OldHash:  record.Hash,
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
			result.Created = append(result.Created, models.AnomalyEvent{
				FilePath: path,
				Action:   models.ActionCreated,
				OldHash:  "",
				NewHash:  sr.Hash,
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
		result.Unreadable = append(result.Unreadable, models.AnomalyEvent{
			FilePath: path,
			Action:   models.ActionUnreadable,
			ScanErr:  sr.Err.Error(),
		})
	}

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
	sort.Slice(result.Unreadable, func(i, j int) bool {
		return result.Unreadable[i].FilePath < result.Unreadable[j].FilePath
	})

	log.Printf("[Scanner] Comparison done: %d modified, %d created, %d deleted, %d unreadable",
		len(result.Modified), len(result.Created), len(result.Deleted), len(result.Unreadable))

	return result
}

func (cr *CompareResult) TotalAnomalies() int {
	return len(cr.Modified) + len(cr.Created) + len(cr.Deleted) + len(cr.Unreadable)
}

func (cr *CompareResult) AllEvents() []models.AnomalyEvent {
	events := make([]models.AnomalyEvent, 0, cr.TotalAnomalies())
	events = append(events, cr.Modified...)
	events = append(events, cr.Created...)
	events = append(events, cr.Unreadable...)
	events = append(events, cr.Deleted...)
	return events
}
