package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/skripsi/fim-ipl/internal/backup"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/quarantine"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

// MaintenanceHandler menangani toggle maintenance mode dan rebuild baseline
// pasca update / instalasi plugin.
type MaintenanceHandler struct {
	scanner *scanner.Scanner
	ledger  *ledger.Ledger
	hub     *realtime.Hub
}

func NewMaintenanceHandler(s *scanner.Scanner, l *ledger.Ledger, hub *realtime.Hub) *MaintenanceHandler {
	return &MaintenanceHandler{scanner: s, ledger: l, hub: hub}
}

func (h *MaintenanceHandler) Enable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	h.scanner.SetMaintenanceMode(true)
	log.Println("[Maintenance] Mode ENABLED - scan cycles akan di-skip")
	publishState(h.hub, h.scanner, "maintenance_enabled")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"maintenance_mode": true,
		"message":          "maintenance mode enabled",
	})
}

func (h *MaintenanceHandler) Disable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	h.scanner.SetMaintenanceMode(false)
	log.Println("[Maintenance] Mode DISABLED - scan cycles resumed")
	publishState(h.hub, h.scanner, "maintenance_disabled")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"maintenance_mode": false,
		"message":          "maintenance mode disabled",
	})
}

// UpdateBaseline melakukan re-scan penuh dan menggantikan baseline lama.
// Digunakan setelah admin selesai update plugin WordPress agar file yang
// legitimately berubah tidak dilaporkan sebagai anomali.
func (h *MaintenanceHandler) UpdateBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.scanner.IsRunning() && !h.scanner.IsMaintenance() {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "stop monitoring or enable maintenance mode before rebuilding baseline",
		})
		return
	}

	log.Println("[Maintenance] Rebuilding baseline...")

	total, err := scanAndSaveBaseline(h.scanner, h.ledger)
	if err != nil {
		log.Printf("[Maintenance] Baseline rebuild failed: %v", err)
		writeBaselineError(w, err)
		return
	}

	log.Printf("[Maintenance] Baseline rebuilt with %d files", total)
	publishState(h.hub, h.scanner, "baseline_rebuilt")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "baseline rebuilt successfully",
		"total_files": total,
	})
}

// -----------------------------------------------------------------------------
// Quarantine
// -----------------------------------------------------------------------------

type QuarantineHandler struct {
	cfg    *config.Config
	ledger *ledger.Ledger
	hub    *realtime.Hub
}

func NewQuarantineHandler(cfg *config.Config, l *ledger.Ledger, hub *realtime.Hub) *QuarantineHandler {
	return &QuarantineHandler{cfg: cfg, ledger: l, hub: hub}
}

// Release mengembalikan permission file dari 000 ke mode ASLINYA (yang
// dicatat saat karantina). Hanya file yang berada di bawah watch path DAN
// berstatus terkarantina terakhir yang boleh dirilis. Bila catatan mode
// asli tidak ditemukan (file dikarantina sebelum v1.1.0), dipakai fallback
// 0644 dan itu dilaporkan di respons agar admin tahu ada yang tidak persis.
func (h *QuarantineHandler) Release(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FilePath string `json:"file_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FilePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file_path required"})
		return
	}

	cleanPath := filepath.Clean(req.FilePath)
	if !isPathWithinRoots(h.cfg.GetWatchPaths(), cleanPath) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "file is outside configured watch paths",
		})
		return
	}

	quarantined, err := h.ledger.IsCurrentlyQuarantined(cleanPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify quarantine state"})
		return
	}
	if !quarantined {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "file is not currently quarantined"})
		return
	}

	restoreMode := os.FileMode(0o644)
	restoredOriginal := false
	if stored, found, err := h.ledger.GetQuarantineMode(cleanPath); err == nil && found {
		restoreMode = os.FileMode(stored)
		restoredOriginal = true
	}

	if err := quarantine.Release(cleanPath, restoreMode); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Catatan mode sudah tidak diperlukan lagi; kegagalan menghapusnya
	// tidak membatalkan release (hanya log, agar tidak menumpuk).
	if err := h.ledger.DeleteQuarantineMode(cleanPath); err != nil {
		log.Printf("[Quarantine] Released %s but failed to clear mode record: %v", cleanPath, err)
	}

	// Catat tindakan manual ke ledger agar jejak "siapa melepas, kapan, file
	// apa" tetap append-only dan ikut terlindungi hash-chain. Kegagalan audit
	// tidak membatalkan pelepasan file (sudah terjadi), tetapi dilaporkan.
	audited := true
	if _, err := h.ledger.AppendBlock(models.AnomalyEvent{
		FilePath: cleanPath,
		Action:   models.ActionReleased,
	}); err != nil {
		audited = false
		log.Printf("[Quarantine] Released %s but failed to record audit block: %v", cleanPath, err)
	}

	log.Printf("[Quarantine] Released: %s (mode %04o, original=%v)", cleanPath, restoreMode, restoredOriginal)
	if h.hub != nil {
		h.hub.Publish("quarantine_released", map[string]string{"file_path": cleanPath})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":           fmt.Sprintf("file permission restored to %04o", restoreMode),
		"restored_original": restoredOriginal,
		"audited":           audited,
	})
}

// -----------------------------------------------------------------------------
// Backup
// -----------------------------------------------------------------------------

type BackupHandler struct {
	mgr *backup.Manager
}

func NewBackupHandler(mgr *backup.Manager) *BackupHandler {
	return &BackupHandler{mgr: mgr}
}

func (h *BackupHandler) Run(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if h.mgr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "backup manager not initialized"})
		return
	}
	if err := h.mgr.RunOnce("manual"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "backup executed",
		"last_run_at": h.mgr.LastRunAt(),
	})
}
