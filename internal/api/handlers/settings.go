package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/skripsi/fim-ipl/internal/backup"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/notifier"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

type SettingsHandler struct {
	cfg      *config.Config
	ledger   *ledger.Ledger
	scanner  *scanner.Scanner
	notifier *notifier.Telegram
	backup   *backup.Manager
	hub      *realtime.Hub
}

func NewSettingsHandler(
	cfg *config.Config,
	l *ledger.Ledger,
	s *scanner.Scanner,
	n *notifier.Telegram,
	bm *backup.Manager,
	hub *realtime.Hub,
) *SettingsHandler {
	return &SettingsHandler{
		cfg:      cfg,
		ledger:   l,
		scanner:  s,
		notifier: n,
		backup:   bm,
		hub:      hub,
	}
}

func (h *SettingsHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	snap := h.cfg.Snapshot()
	settings := map[string]interface{}{
		"watch_paths":         snap.WatchPaths,
		"scan_interval_sec":   snap.ScanIntervalSec,
		"worker_count":        snap.WorkerCount,
		"telegram_chat_id":    snap.TelegramChatID,
		"telegram_configured": h.notifier.IsConfigured(),
		"backup_webhook_url":  snap.BackupWebhookURL,
		"allowed_origins":     snap.AllowedOrigins,
		"is_monitoring":       h.scanner.IsRunning(),
		"maintenance_mode":    h.scanner.IsMaintenance(),
		"auditor_username":    snap.AuditorUsername,
		"auditor_configured":  snap.AuditorUsername != "" && snap.AuditorPassword != "",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (h *SettingsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		WatchPaths       []string `json:"watch_paths"`
		ScanIntervalSec  int      `json:"scan_interval_sec"`
		WorkerCount      int      `json:"worker_count"`
		TelegramToken    string   `json:"telegram_token"`
		TelegramChatID   string   `json:"telegram_chat_id"`
		BackupWebhookURL string   `json:"backup_webhook_url"`
		AllowedOrigins   []string `json:"allowed_origins"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.ScanIntervalSec != 0 && (req.ScanIntervalSec < 30 || req.ScanIntervalSec > 86400) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scan_interval_sec must be between 30 and 86400"})
		return
	}
	if req.WorkerCount != 0 && (req.WorkerCount < 1 || req.WorkerCount > 16) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "worker_count must be between 1 and 16"})
		return
	}
	if err := validateWebhookURL(req.BackupWebhookURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	watchPaths := req.WatchPaths
	var err error
	if len(req.WatchPaths) > 0 {
		watchPaths, err = validateWatchPaths(req.WatchPaths)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	var origins []string
	if req.AllowedOrigins != nil {
		origins, err = validateOrigins(req.AllowedOrigins)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	h.cfg.Update(func(c *config.Config) {
		if len(watchPaths) > 0 {
			c.WatchPaths = watchPaths
		}
		if req.ScanIntervalSec > 0 {
			c.ScanIntervalSec = req.ScanIntervalSec
		}
		if req.WorkerCount > 0 {
			c.WorkerCount = req.WorkerCount
		}
		if req.TelegramToken != "" {
			c.TelegramToken = req.TelegramToken
		}
		if req.TelegramChatID != "" {
			c.TelegramChatID = req.TelegramChatID
		}
		// BackupWebhookURL: string kosong artinya "hapus webhook".
		c.BackupWebhookURL = req.BackupWebhookURL
		// AllowedOrigins: array kosong eksplisit berarti "izinkan semua".
		if req.AllowedOrigins != nil {
			c.AllowedOrigins = origins
		}
	})

	if err := h.cfg.Persist(); err != nil {
		log.Printf("[Settings] Failed to persist config: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save settings"})
		return
	}

	snap := h.cfg.Snapshot()
	h.scanner.UpdateConfig(snap.WorkerCount, snap.WatchPaths, snap.ScanIntervalSec)
	h.notifier.UpdateConfig(snap.TelegramToken, snap.TelegramChatID)
	if h.backup != nil {
		h.backup.UpdateWebhook(snap.BackupWebhookURL)
	}

	log.Println("[Settings] Configuration updated and saved")
	publishState(h.hub, h.scanner, "settings_updated")

	writeJSON(w, http.StatusOK, map[string]string{"message": "settings updated successfully"})
}

func (h *SettingsHandler) StartMonitoring(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.scanner.IsRunning() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "monitoring already running"})
		return
	}

	baselineCount, err := h.ledger.GetBaselineCount()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read baseline"})
		return
	}
	if baselineCount == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "initialize baseline before starting monitoring"})
		return
	}

	h.scanner.StartMonitoring(h.cfg.GetScanInterval())
	log.Println("[Settings] Monitoring started")
	publishState(h.hub, h.scanner, "monitoring_started")

	writeJSON(w, http.StatusOK, map[string]string{"message": "monitoring started"})
}

func (h *SettingsHandler) StopMonitoring(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if !h.scanner.IsRunning() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "monitoring not running"})
		return
	}

	h.scanner.StopMonitoring()
	log.Println("[Settings] Monitoring stopped")
	publishState(h.hub, h.scanner, "monitoring_stopped")

	writeJSON(w, http.StatusOK, map[string]string{"message": "monitoring stopped"})
}

func (h *SettingsHandler) InitializeBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.scanner.IsRunning() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "stop monitoring before re-initializing baseline"})
		return
	}

	log.Println("[Settings] Initializing baseline...")

	total, err := scanAndSaveBaseline(h.scanner, h.ledger)
	if err != nil {
		log.Printf("[Settings] Baseline initialization failed: %v", err)
		writeBaselineError(w, err)
		return
	}

	log.Printf("[Settings] Baseline initialized with %d files", total)
	publishState(h.hub, h.scanner, "baseline_initialized")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "baseline initialized successfully",
		"total_files": total,
	})
}

func (h *SettingsHandler) TestTelegram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Body opsional: jika admin mengetik token/chat ID baru tetapi belum
	// menyimpan, uji memakai nilai yang diketik agar tidak membingungkan.
	var req struct {
		TelegramToken  string `json:"telegram_token"`
		TelegramChatID string `json:"telegram_chat_id"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
	}

	tg := h.notifier
	if strings.TrimSpace(req.TelegramToken) != "" || strings.TrimSpace(req.TelegramChatID) != "" {
		snap := h.cfg.Snapshot()
		token := snap.TelegramToken
		chatID := snap.TelegramChatID
		if v := strings.TrimSpace(req.TelegramToken); v != "" {
			token = v
		}
		if v := strings.TrimSpace(req.TelegramChatID); v != "" {
			chatID = v
		}
		tg = notifier.NewTelegram(token, chatID)
	}

	if err := tg.SendTestMessage(); err != nil {
		log.Printf("[Settings] Telegram test failed: %v", err)
		status := http.StatusBadGateway
		if strings.Contains(err.Error(), "not configured") {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": "telegram test failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "test message sent successfully"})
}
