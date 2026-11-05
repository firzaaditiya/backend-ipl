package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/skripsi/fim-ipl/internal/api"
	"github.com/skripsi/fim-ipl/internal/backup"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/metrics"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/notifier"
	"github.com/skripsi/fim-ipl/internal/quarantine"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

// CriticalAnomalyThreshold: jumlah anomali dalam satu cycle yang memicu
// backup ledger otomatis di luar jadwal 24 jam.
const CriticalAnomalyThreshold = 5

// unresolved mencatat anomali yang belum berhasil dikarantina (atau file yang
// tidak terbaca). Deteksi berulang dengan fingerprint sama tidak ditulis lagi
// ke ledger setiap siklus, tetapi tetap dicatat di log agar tidak silent.
var (
	unresolvedMu sync.Mutex
	unresolved   = make(map[string]string)

	scanAlertMu sync.Mutex
	lastScanErr string
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[FIM-IPL] Starting File Integrity Monitoring System...")

	configPath := getConfigPath()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("[FIM-IPL] Failed to load config: %v", err)
	}

	log.Printf("[FIM-IPL] Config loaded. Server port: %s, Workers: %d", cfg.ServerPort, cfg.WorkerCount)
	log.Printf("[FIM-IPL] Watch paths: %v", cfg.WatchPaths)

	db, err := ledger.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("[FIM-IPL] Failed to initialize ledger: %v", err)
	}
	defer db.Close()
	log.Println("[FIM-IPL] Ledger initialized")

	sc := scanner.New(cfg.GetWorkerCount(), cfg.GetWatchPaths())
	log.Println("[FIM-IPL] Scanner initialized")

	tg := notifier.NewTelegram(cfg.TelegramToken, cfg.TelegramChatID)
	log.Println("[FIM-IPL] Telegram notifier initialized")

	// Backup manager: default interval 24 jam.
	bm := backup.NewManager(db, tg, cfg.BackupWebhookURL, 24*time.Hour)
	bm.Start()
	log.Println("[FIM-IPL] Backup manager started (24h interval)")

	// Hub realtime untuk SSE (dashboard live update).
	hub := realtime.NewHub()
	log.Println("[FIM-IPL] Realtime hub initialized")

	// Antrean alert Telegram (sejak v1.5.0): pengiriman berjalan di
	// goroutine terpisah agar API Telegram yang lambat/mati tidak pernah
	// menahan pipeline scan.
	alertJobs := make(chan alertJob, 64)
	alertStop := make(chan struct{})
	startAlertWorker(tg, alertJobs, alertStop)

	sc.RegisterScanCycle(func() {
		runFullScanCycle(sc, db, bm, hub, alertJobs)
	})

	router := api.NewRouter(cfg, db, sc, tg, bm, hub)

	snap := cfg.Snapshot()

	// Secret HMAC webhook (env-only, FIM_WEBHOOK_SECRET). Kosong berarti
	// webhook dikirim tanpa tanda tangan.
	bm.SetWebhookSecret(snap.WebhookSecret)

	// Auto-resume monitoring (sejak v1.1.0): status monitoring dipertahankan
	// di config.json oleh handler Start/Stop, jadi restart proses (mis.
	// systemctl restart, reboot VPS) TIDAK mematikan perlindungan secara
	// diam-diam. Shutdown proses tidak mengubah flag ini; hanya tombol Stop
	// di dashboard yang boleh mematikannya. Bila baseline kosong (mis. DB
	// di-reset), flag dibersihkan agar tidak mencoba start tiap boot.
	if snap.MonitoringEnabled {
		if count, err := db.GetBaselineCount(); err != nil {
			log.Printf("[FIM-IPL] Auto-resume skipped: cannot read baseline: %v", err)
		} else if count == 0 {
			log.Println("[FIM-IPL] Auto-resume skipped: baseline empty, clearing flag")
			cfg.Update(func(c *config.Config) { c.MonitoringEnabled = false })
			_ = cfg.Persist()
		} else {
			sc.StartMonitoring(snap.ScanIntervalSec)
			log.Printf("[FIM-IPL] Monitoring auto-resumed (%d baseline files)", count)
		}
	}

	server := &http.Server{
		Addr:              snap.ServerPort,
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown handler
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("[FIM-IPL] Shutting down...")
		sc.StopMonitoring()
		bm.Stop()
		hub.Close()
		close(alertStop)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("[FIM-IPL] REST API server starting on %s", cfg.ServerPort)
	log.Printf("[FIM-IPL] Login endpoint: %s", cfg.LoginPath)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[FIM-IPL] Server failed: %v", err)
	}

	log.Println("[FIM-IPL] Server stopped gracefully")
}

func getConfigPath() string {
	if p := os.Getenv("FIM_CONFIG_PATH"); p != "" {
		return p
	}
	return "./data/config.json"
}

func eventFingerprint(e models.AnomalyEvent) string {
	return e.Action + "|" + e.OldHash + "|" + e.NewHash + "|" + e.ScanErr + "|" + e.QuarantineErr
}

func isUnresolved(path, fingerprint string) bool {
	unresolvedMu.Lock()
	defer unresolvedMu.Unlock()
	return unresolved[path] == fingerprint
}

func markUnresolved(path, fingerprint string) {
	unresolvedMu.Lock()
	unresolved[path] = fingerprint
	unresolvedMu.Unlock()
}

func clearUnresolved(path string) {
	unresolvedMu.Lock()
	delete(unresolved, path)
	unresolvedMu.Unlock()
}

// alertJob adalah satu pekerjaan pengiriman Telegram. Seluruh alert
// Telegram berjalan lewat antrean ini (sejak v1.5.0) agar API Telegram yang
// lambat/mati tidak pernah menahan pipeline scan: pengiriman sinkron (retry
// sampai ~48 detik per pesan, sampai ~190 detik per siklus) bisa melewati
// interval 120 detik dan membuat siklus berikut di-skip sebagai overlap —
// tepat saat ketepatan deteksi paling dibutuhkan.
type alertJob struct {
	kind     string // "system" | "failures" | "blocks"
	title    string
	message  string
	failures []notifier.QuarantineFailure
	blocks   []*models.Block
	recorded int
}

func startAlertWorker(tg *notifier.Telegram, jobs <-chan alertJob, stop <-chan struct{}) {
	go func() {
		for {
			select {
			case job := <-jobs:
				if tg == nil || !tg.IsConfigured() {
					continue
				}
				switch job.kind {
				case "system":
					if err := tg.SendSystemAlert(job.title, job.message); err != nil {
						log.Printf("[Telegram] System alert failed: %v", err)
					}
				case "failures":
					if err := tg.SendQuarantineFailures(job.failures); err != nil {
						log.Printf("[Telegram] Quarantine-failure alert failed: %v", err)
					}
				case "blocks":
					if len(job.blocks) <= 3 {
						for _, block := range job.blocks {
							if err := tg.SendAlert(block); err != nil {
								log.Printf("[Telegram] Alert failed: %v", err)
							}
						}
					} else if err := tg.SendBatchAlert(job.blocks, job.recorded); err != nil {
						log.Printf("[Telegram] Batch alert failed: %v", err)
					}
				}
			case <-stop:
				return
			}
		}
	}()
}

// enqueueAlert mengirim pekerjaan ke antrean tanpa pernah memblokir
// pipeline scan. Bila antrean penuh (64 pekerjaan tertunda — jauh di atas
// volume normal ~5 per siklus), pekerjaan dibuang dan dicatat di log.
// jobs boleh nil (pengujian tanpa worker): pekerjaan dibuang diam-diam.
func enqueueAlert(jobs chan<- alertJob, job alertJob) {
	if jobs == nil {
		return
	}
	select {
	case jobs <- job:
	default:
		log.Printf("[Telegram] Alert queue full, dropping %s alert", job.kind)
	}
}

// notifyScanFailure mengirim satu peringatan per jenis error. Pengulangan
// setiap siklus tidak dikirim ulang agar kanal tidak banjir, tetapi tetap
// dicatat di log oleh caller.
func notifyScanFailure(jobs chan<- alertJob, err error) {
	message := err.Error()

	scanAlertMu.Lock()
	if message == lastScanErr {
		scanAlertMu.Unlock()
		return
	}
	lastScanErr = message
	scanAlertMu.Unlock()

	enqueueAlert(jobs, alertJob{kind: "system", title: "PEMINDAIAN GAGAL", message: message})
}

func clearScanFailure() {
	scanAlertMu.Lock()
	lastScanErr = ""
	scanAlertMu.Unlock()
}

// baselineUpdateAllowed memastikan file berbahaya tidak pernah dianggap
// "normal" saat karantina gagal. DELETED selalu boleh dihapus dari baseline;
// CREATED/MODIFIED/MODE_CHANGED hanya boleh setelah chmod berhasil;
// UNREADABLE tidak pernah boleh karena isi terbaru tidak pernah berhasil
// dibaca.
func baselineUpdateAllowed(action string, qres quarantine.Result) bool {
	switch action {
	case models.ActionDeleted:
		return true
	case models.ActionCreated, models.ActionModified, models.ActionModeChanged:
		return qres.Success
	default:
		return false
	}
}

// filterActiveQuarantine membuang hasil hash yang gagal hanya karena file
// memang sedang dikarantina (chmod 000 / ReadOnly), bukan karena serangan baru.
// Baseline untuk path tersebut juga tidak dibandingkan agar tidak muncul
// DELETED palsu. File yang hilang, berubah ukuran/mtime, atau izinnya sudah
// dikembalikan tetap dibandingkan normal.
func filterActiveQuarantine(results []models.ScanResult, baseline map[string]models.FileRecord, quarantined map[string]bool) []models.ScanResult {
	if len(quarantined) == 0 || len(results) == 0 {
		return results
	}

	filtered := make([]models.ScanResult, 0, len(results))
	for _, r := range results {
		if r.Err == nil || !quarantined[r.Path] {
			filtered = append(filtered, r)
			continue
		}

		rec, inBaseline := baseline[r.Path]
		if !inBaseline {
			// File baru yang tidak terbaca dan bukan hasil karantina kita:
			// tetap laporkan sebagai UNREADABLE.
			filtered = append(filtered, r)
			continue
		}

		info, err := os.Lstat(r.Path)
		if err != nil || !isQuarantineEffective(info) {
			filtered = append(filtered, r)
			continue
		}
		if info.Size() != rec.Size || !rec.ModTime.Equal(info.ModTime()) {
			// Isi berubah setelah karantina; jangan diamkan.
			filtered = append(filtered, r)
			continue
		}

		delete(baseline, r.Path)
	}
	return filtered
}

func isQuarantineEffective(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		// os.Chmod(000) di Windows menjadi atribut ReadOnly.
		return info.Mode().Perm()&0o200 == 0
	}
	return info.Mode().Perm()&0o444 == 0
}

// runFullScanCycle adalah pipeline eksekusi satu siklus scan:
//
//	metrics.Start()  →  scanner.Scan()  →  compare  →  quarantine  →  ledger.AppendBlock  →  metrics.Finish → saveMetric  →  broadcast SSE  →  telegram alert (async, via antrean)  →  optional backup
func runFullScanCycle(sc *scanner.Scanner, db *ledger.Ledger, bm *backup.Manager, hub *realtime.Hub, alertJobs chan<- alertJob) {
	// Satu panic di pipeline tidak boleh mematikan daemon. FinishScan (defer
	// yang didaftarkan di bawah) tetap dijalankan lebih dulu karena urutan LIFO.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[Scan] PANIC recovered: %v\n%s", rec, debug.Stack())
			if hub != nil {
				hub.Publish("status", map[string]interface{}{
					"reason":           "scan_panic",
					"is_monitoring":    sc.IsRunning(),
					"maintenance_mode": sc.IsMaintenance(),
				})
			}
		}
	}()

	cycle := metrics.Start()

	// 0) Maintenance mode gate
	if sc.IsMaintenance() {
		cycle.MarkSkipped("maintenance_mode")
		m := cycle.Finish(0, 0, 0)
		_ = db.SaveMetric(m)
		broadcastScan(hub, m)
		log.Println("[Scan] Skipped: maintenance mode active")
		return
	}

	// 1) Overlap guard
	if !sc.TryStartScan() {
		cycle.MarkSkipped("overlap")
		m := cycle.Finish(0, 0, 0)
		_ = db.SaveMetric(m)
		broadcastScan(hub, m)
		log.Println("[Scan] Skipped: previous scan cycle still running")
		return
	}
	defer sc.FinishScan()

	log.Println("[Scan] Starting scan cycle...")

	// 2) Scan
	results, err := sc.Scan()
	if err != nil {
		log.Printf("[Scan] Error during scan: %v", err)
		notifyScanFailure(alertJobs, err)
		m := cycle.Finish(0, 0, 0)
		_ = db.SaveMetric(m)
		broadcastScan(hub, m)
		return
	}
	clearScanFailure()

	// File yang berhasil dibaca menandakan masalah sementara sudah pulih.
	// Hapus penanda unresolved agar masalah baru pada path yang sama tetap
	// dilaporkan (bukan selamanya dianggap duplikat).
	for _, r := range results {
		if r.Err == nil {
			clearUnresolved(r.Path)
		}
	}

	baseline, err := db.GetBaseline()
	if err != nil {
		log.Printf("[Scan] Error getting baseline: %v", err)
		m := cycle.Finish(len(results), 0, 0)
		_ = db.SaveMetric(m)
		broadcastScan(hub, m)
		return
	}

	if len(baseline) == 0 {
		log.Println("[Scan] No baseline found. Please initialize baseline first.")
		m := cycle.Finish(len(results), 0, 0)
		_ = db.SaveMetric(m)
		broadcastScan(hub, m)
		return
	}

	// File yang sedang dikarantina memang tidak dapat dibaca di Linux.
	// Jangan laporkan sebagai UNREADABLE/DELETED berulang setiap siklus.
	quarantinedPaths, qerr := db.GetCurrentlyQuarantinedPaths()
	if qerr != nil {
		log.Printf("[Scan] Failed to load quarantine state: %v", qerr)
	} else {
		results = filterActiveQuarantine(results, baseline, quarantinedPaths)
	}

	// 3) Compare (paralelisme pembanding mengikuti konfigurasi worker).
	compareResult := scanner.CompareWithBaseline(results, baseline, sc.WorkerCount())
	totalAnomalies := compareResult.TotalAnomalies()

	// Adopsi mode baseline lama (Mode == 0, dari sebelum v1.5.0): satu
	// transaksi, tanpa event — agar perubahan izin pada siklus berikutnya
	// benar-benar terdeteksi dan 3901 file lama tidak sekaligus
	// dilaporkan berubah pada siklus pertama setelah upgrade.
	if len(compareResult.ModeAdoptions) > 0 {
		if err := db.AdoptBaselineModes(compareResult.ModeAdoptions); err != nil {
			log.Printf("[Scan] Failed to adopt baseline modes: %v", err)
		} else {
			log.Printf("[Scan] Adopted modes for %d baseline file(s) (pre-v1.5.0 records)", len(compareResult.ModeAdoptions))
		}
	}
	if compareResult.SkippedOversize > 0 {
		log.Printf("[Scan] %d file(s) skipped (oversize >50 MB, non-kode): isi tidak diperiksa", compareResult.SkippedOversize)
	}

	if totalAnomalies == 0 {
		log.Println("[Scan] Scan complete. No anomalies detected.")
		m := cycle.Finish(len(results), 0, 0)
		m.SkippedOversize = compareResult.SkippedOversize
		_ = db.SaveMetric(m)
		broadcastScan(hub, m)
		return
	}

	log.Printf("[Scan] ALERT: %d anomalies detected!", totalAnomalies)

	// Map hasil scan untuk lookup
	scanMap := make(map[string]models.ScanResult, len(results))
	for _, r := range results {
		if r.Err == nil {
			scanMap[r.Path] = r
		}
	}

	// 4) Quarantine + AppendBlock (per event)
	var blocks []*models.Block
	var quarantinedCount int
	var quarantineFailures []notifier.QuarantineFailure

	for _, event := range compareResult.AllEvents() {
		// Karantina untuk CREATED/MODIFIED/MODE_CHANGED/UNREADABLE.
		// DELETED tidak punya file.
		attemptQuarantine := event.Action != models.ActionDeleted
		var qres quarantine.Result

		if attemptQuarantine {
			qres = quarantine.Apply(event.FilePath)
			event.Quarantined = qres.Success

			switch {
			case qres.Err != nil:
				event.QuarantineErr = qres.Err.Error()
				log.Printf("[Quarantine] FAILED for %s: %v", event.FilePath, qres.Err)
			case qres.SkipReason != "":
				event.QuarantineErr = qres.SkipReason
				log.Printf("[Quarantine] SKIPPED for %s: %s", event.FilePath, qres.SkipReason)
			default:
				quarantinedCount++
				log.Printf("[Quarantine] OK: %s (chmod 000)", event.FilePath)
				// Catat permission asli agar Release mengembalikannya
				// persis (bukan default 0644). Gagal mencatat tidak
				// membatalkan karantina; Release memakai fallback 0644.
				if err := db.RecordQuarantineMode(event.FilePath, uint32(qres.OriginalMode)); err != nil {
					log.Printf("[Quarantine] Failed to record original mode for %s: %v", event.FilePath, err)
				}
			}
		}

		// Alasan file tidak dapat dipindai tetap disimpan di ledger. Bila
		// karantina juga gagal, kedua alasan digabung agar admin tahu bahwa
		// file belum benar-benar dilumpuhkan.
		if event.Action == models.ActionUnreadable && event.ScanErr != "" {
			if event.QuarantineErr != "" {
				event.QuarantineErr = "pemindaian: " + event.ScanErr + "; karantina: " + event.QuarantineErr
			} else {
				event.QuarantineErr = "pemindaian: " + event.ScanErr
			}
		}

		// Deteksi berulang untuk masalah yang sama tidak ditulis ulang setiap
		// siklus. Alasan (Ops/ScanErr) ikut fingerprint agar perubahan jenis
		// masalah tetap memicu alert baru.
		fingerprint := eventFingerprint(event)
		persistent := event.Action == models.ActionUnreadable ||
			(attemptQuarantine && !qres.Success)
		if persistent && isUnresolved(event.FilePath, fingerprint) {
			log.Printf("[Scan] Unresolved anomaly still present (alert suppressed): %s", event.FilePath)
			continue
		}

		// Append ke ledger. Baseline TIDAK boleh diperbarui bila append gagal,
		// agar temuan yang sama dicoba lagi pada siklus berikutnya.
		block, err := db.AppendBlock(event)
		if err != nil {
			log.Printf("[Scan] Failed to record anomaly: %v", err)
			continue
		}
		blocks = append(blocks, block)

		if persistent {
			markUnresolved(event.FilePath, fingerprint)
		} else {
			clearUnresolved(event.FilePath)
		}

		if attemptQuarantine && !qres.Success {
			reason := event.QuarantineErr
			if reason == "" {
				reason = "karantina dilewati"
			}
			quarantineFailures = append(quarantineFailures, notifier.QuarantineFailure{
				FilePath: event.FilePath,
				Reason:   reason,
			})
		}

		// Auto-update baseline HANYA setelah file berhasil dikarantina.
		// Bila karantina gagal/dilewati, baseline lama dipertahankan supaya
		// file berbahaya tidak "dianggap normal" pada siklus berikutnya.
		switch event.Action {
		case models.ActionDeleted:
			if err := db.RemoveBaselineEntry(event.FilePath); err != nil {
				log.Printf("[Scan] Failed to remove baseline entry: %v", err)
			}
			// Catatan mode karantina sudah tidak relevan: file-nya hilang.
			if err := db.DeleteQuarantineMode(event.FilePath); err != nil {
				log.Printf("[Scan] Failed to clear quarantine mode record: %v", err)
			}
		case models.ActionModified, models.ActionCreated, models.ActionModeChanged:
			if !baselineUpdateAllowed(event.Action, qres) {
				log.Printf("[Scan] Baseline retained for %s (quarantine not successful)", event.FilePath)
				break
			}
			if sr, ok := scanMap[event.FilePath]; ok {
				record := models.FileRecord{
					Path:      sr.Path,
					Hash:      sr.Hash,
					Mode:      sr.Mode,
					Size:      sr.Size,
					ModTime:   sr.ModTime,
					ScannedAt: time.Now(),
				}
				if err := db.UpdateBaselineEntry(record); err != nil {
					log.Printf("[Scan] Failed to update baseline entry: %v", err)
				}
			}
		case models.ActionUnreadable:
			log.Printf("[Scan] Baseline retained for %s (file remains unreadable)", event.FilePath)
		}
	}

	// 5) Metrics. Anomali yang sudah tercatat dan masih unresolved tidak
	// dihitung ulang agar grafik tidak naik tanpa ada temuan baru.
	recorded := len(blocks)
	m := cycle.Finish(len(results), recorded, quarantinedCount)
	m.SkippedOversize = compareResult.SkippedOversize
	if err := db.SaveMetric(m); err != nil {
		log.Printf("[Metrics] Failed to save: %v", err)
	}
	log.Printf("[Metrics] cycle: elapsed=%dms mem_alloc=%.2fMB files=%d anomalies=%d quarantined=%d skipped_oversize=%d",
		m.ElapsedMs, float64(m.MemAllocBytes)/1024.0/1024.0, m.FilesScanned, m.Anomalies, m.Quarantined, m.SkippedOversize)
	broadcastScan(hub, m)

	// 6) Telegram alerts — async lewat antrean (lihat startAlertWorker):
	// pipeline scan tidak pernah menunggu jaringan.
	if len(quarantineFailures) > 0 {
		enqueueAlert(alertJobs, alertJob{kind: "failures", failures: quarantineFailures})
	}
	if len(blocks) > 0 {
		enqueueAlert(alertJobs, alertJob{kind: "blocks", blocks: blocks, recorded: recorded})
	}

	// 7) Trigger backup jika temuan BARU di siklus ini dianggap kritis.
	if recorded >= CriticalAnomalyThreshold && bm != nil {
		go func(n int) {
			if err := bm.RunOnce("critical-anomaly"); err != nil {
				log.Printf("[Backup] Critical-anomaly backup failed: %v", err)
			} else {
				log.Printf("[Backup] Critical-anomaly backup executed (n=%d)", n)
			}
		}(recorded)
	}

	log.Printf("[Scan] Scan cycle complete. %d detected, %d recorded to ledger, %d suppressed (unresolved).",
		totalAnomalies, recorded, totalAnomalies-recorded)
}

// broadcastScan menyiarkan ringkasan siklus scan ke klien SSE. Dipanggil
// setelah metrik tersimpan agar dashboard bisa memperbarui tanpa polling.
func broadcastScan(hub *realtime.Hub, m models.ScanMetric) {
	if hub == nil {
		return
	}
	hub.Publish("scan", map[string]interface{}{
		"elapsed_ms":    m.ElapsedMs,
		"files_scanned": m.FilesScanned,
		"anomalies":     m.Anomalies,
		"quarantined":   m.Quarantined,
		"at":            m.Timestamp,
	})
}
