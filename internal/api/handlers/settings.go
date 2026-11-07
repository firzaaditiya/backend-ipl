package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/backup"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
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

	// Auditor hanya butuh membaca konfigurasi operasional. Tujuan
	// notifikasi (chat ID Telegram) dan URL webhook backup bukan kebutuhan
	// Auditor, jadi disembunyikan dari respons role tersebut.
	isAuditor := true
	if claims, ok := middleware.ParseClaimsWithRevocation(r, snap.JWTSecret, snap.SessionEpoch, func(jti string) bool {
		if h.ledger == nil {
			return false
		}
		return h.ledger.IsTokenRevoked(jti)
	}); ok {
		isAuditor = claims.Role == middleware.RoleAuditor
	}
	telegramChatID := snap.TelegramChatID
	backupWebhookURL := snap.BackupWebhookURL
	if isAuditor {
		telegramChatID = ""
		backupWebhookURL = ""
	}

	settings := map[string]interface{}{
		"watch_paths":         snap.WatchPaths,
		"exclude_globs":       snap.ExcludeGlobs,
		"scan_interval_sec":   snap.ScanIntervalSec,
		"worker_count":        snap.WorkerCount,
		"telegram_chat_id":    telegramChatID,
		"telegram_configured": h.notifier.IsConfigured(),
		// Sumber kredensial Telegram (T-07): UI menonaktifkan kolom
		// Telegram bila nilainya berasal dari environment (fim.env).
		"telegram_token_from_env":   snap.TelegramTokenFromEnv,
		"telegram_chat_id_from_env": snap.TelegramChatIDFromEnv,
		"backup_webhook_url":        backupWebhookURL,
		"allowed_origins":           snap.AllowedOrigins,
		"is_monitoring":             h.scanner.IsRunning(),
		"maintenance_mode":          h.scanner.IsMaintenance(),
		"auditor_username":          snap.AuditorUsername,
		"auditor_configured":        snap.AuditorUsername != "" && snap.AuditorPassword != "",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (h *SettingsHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	actor := actorFromRequest(r, h.cfg, h.ledger)

	var req struct {
		WatchPaths       []string `json:"watch_paths"`
		ExcludeGlobs     []string `json:"exclude_globs"`
		ScanIntervalSec  int      `json:"scan_interval_sec"`
		WorkerCount      int      `json:"worker_count"`
		TelegramToken    string   `json:"telegram_token"`
		TelegramChatID   *string  `json:"telegram_chat_id"`
		BackupWebhookURL *string  `json:"backup_webhook_url"`
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
	if req.BackupWebhookURL != nil {
		if err := validateWebhookURL(*req.BackupWebhookURL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	// Kredensial Telegram yang berasal dari environment (fim.env) tidak
	// boleh diubah lewat API (T-07): nilai di config.json akan kalah
	// dengan env pada boot berikutnya, dan dengan
	// FIM_REQUIRE_EXTERNAL_SECRETS=1, menulis token ke config.json justru
	// membuat boot berikutnya GAGAL. Tolak dengan pesan yang jelas, bukan
	// diam-diam mengabaikan.
	envSnap := h.cfg.Snapshot()
	if req.TelegramToken != "" && envSnap.TelegramTokenFromEnv {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "telegram_token is managed via environment (fim.env); remove it from fim.env to manage it here"})
		return
	}
	if req.TelegramChatID != nil && envSnap.TelegramChatIDFromEnv {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "telegram_chat_id is managed via environment (fim.env); remove it from fim.env to manage it here"})
		return
	}
	// Pola pengecualian divalidasi sintaksnya sebelum disimpan (T-05):
	// pola yang tidak valid tidak boleh masuk config.
	if req.ExcludeGlobs != nil {
		if err := scanner.ValidateGlobs(req.ExcludeGlobs); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
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

	// Nama field yang benar-benar diubah (T-03): hanya nama field, TIDAK
	// pernah nilainya — nilai bisa berupa token atau rahasia. Urutan
	// tetap sesuai struct request agar deterministik. Bila tidak ada
	// field yang diubah, tidak ada blok audit (bukan mutasi).
	var changed []string
	if len(watchPaths) > 0 {
		changed = append(changed, "watch_paths")
	}
	if req.ExcludeGlobs != nil {
		changed = append(changed, "exclude_globs")
	}
	if req.ScanIntervalSec > 0 {
		changed = append(changed, "scan_interval_sec")
	}
	if req.WorkerCount > 0 {
		changed = append(changed, "worker_count")
	}
	if req.TelegramToken != "" {
		changed = append(changed, "telegram_token")
	}
	if req.TelegramChatID != nil {
		changed = append(changed, "telegram_chat_id")
	}
	if req.BackupWebhookURL != nil {
		changed = append(changed, "backup_webhook_url")
	}
	if req.AllowedOrigins != nil {
		changed = append(changed, "allowed_origins")
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
		// ExcludeGlobs: nil = field tidak dikirim (biarkan nilai lama);
		// array kosong eksplisit = hapus semua pola (kebijakan uploads
		// bawaan tetap berlaku).
		if req.ExcludeGlobs != nil {
			c.ExcludeGlobs = req.ExcludeGlobs
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
		// TelegramChatID: pointer nil = field tidak dikirim (biarkan nilai
		// lama); string kosong eksplisit = hapus chat ID — sama seperti
		// BackupWebhookURL di atas. Sebelum v1.5.0 field ini bertipe string
		// biasa sehingga chat ID tidak pernah bisa dikosongkan dari UI.
		if req.TelegramChatID != nil {
			c.TelegramChatID = *req.TelegramChatID
		}
		// BackupWebhookURL: pointer nil = field tidak dikirim (biarkan nilai
		// lama); string kosong eksplisit = hapus webhook. Sebelum v1.4.0,
		// update parsial tanpa field ini menghapus webhook secara diam-diam.
		if req.BackupWebhookURL != nil {
			c.BackupWebhookURL = *req.BackupWebhookURL
		}
		// AllowedOrigins: array kosong eksplisit berarti "tidak ada origin
		// lintas situs yang diizinkan" (fail-closed, sejak v1.4.0) —
		// bukan "izinkan semua". Komentar lama yang menulis sebaliknya
		// sudah diperbaiki di v1.5.0.
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
	h.scanner.UpdateConfig(snap.WorkerCount, snap.WatchPaths, snap.ScanIntervalSec, snap.ExcludeGlobs)
	h.notifier.UpdateConfig(snap.TelegramToken, snap.TelegramChatID)
	if h.backup != nil {
		h.backup.UpdateWebhook(snap.BackupWebhookURL)
	}

	log.Println("[Settings] Configuration updated and saved")
	publishState(h.hub, h.scanner, "settings_updated")

	// Catat perubahan pengaturan ke ledger (T-03). Bila tidak ada field
	// yang berubah, tidak ada blok (bukan mutasi).
	resp := map[string]interface{}{"message": "settings updated successfully"}
	if len(changed) > 0 {
		resp["audited"] = appendAdminBlock(h.ledger, actor, models.ActionSettingsChanged, strings.Join(changed, ", "))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *SettingsHandler) StartMonitoring(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	actor := actorFromRequest(r, h.cfg, h.ledger)

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

	// Status monitoring DIPERTAHANKAN di config.json SEBELUM scanner
	// dijalankan: bila proses mati/restart, daemon tahu monitoring harus
	// dilanjutkan otomatis (lihat main.go). Gagal persist = jangan mulai,
	// agar status di disk tidak berbohong.
	h.cfg.Update(func(c *config.Config) { c.MonitoringEnabled = true })
	if err := h.cfg.Persist(); err != nil {
		log.Printf("[Settings] Failed to persist monitoring state: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save monitoring state"})
		return
	}

	h.scanner.StartMonitoring(h.cfg.GetScanInterval())
	log.Println("[Settings] Monitoring started")
	publishState(h.hub, h.scanner, "monitoring_started")

	snap := h.cfg.Snapshot()
	audited := appendAdminBlock(h.ledger, actor, models.ActionMonitoringStart,
		fmt.Sprintf("interval %d detik, %d worker", snap.ScanIntervalSec, snap.WorkerCount))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "monitoring started",
		"audited": audited,
	})
}

func (h *SettingsHandler) StopMonitoring(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	actor := actorFromRequest(r, h.cfg, h.ledger)

	if !h.scanner.IsRunning() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "monitoring not running"})
		return
	}

	// Sama seperti Start: status di disk diubah dulu, baru scanner
	// dihentikan. Restart proses TIDAK memanggil handler ini, jadi flag
	// tidak ikut terhapus saat systemctl restart — itulah yang membuat
	// auto-resume di main.go bekerja.
	h.cfg.Update(func(c *config.Config) { c.MonitoringEnabled = false })
	if err := h.cfg.Persist(); err != nil {
		log.Printf("[Settings] Failed to persist monitoring state: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save monitoring state"})
		return
	}

	h.scanner.StopMonitoring()
	log.Println("[Settings] Monitoring stopped")
	publishState(h.hub, h.scanner, "monitoring_stopped")

	audited := appendAdminBlock(h.ledger, actor, models.ActionMonitoringStop, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "monitoring stopped",
		"audited": audited,
	})
}

func (h *SettingsHandler) InitializeBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	actor := actorFromRequest(r, h.cfg, h.ledger)

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

	// Digest baseline ikut dicatat di blok (T-04). Bila digest gagal
	// dihitung (baca DB gagal — praktis tidak mungkin setelah rebuild
	// berhasil), blok tetap dicatat tanpa digest agar jejak rebuild tidak
	// hilang; VerifyBaselineDigest akan melaporkannya sebagai blok tanpa
	// digest, bukan sebagai cocok.
	detail := fmt.Sprintf("baseline dibuat: %d berkas", total)
	audited := false
	if digest, count, derr := h.ledger.BaselineDigest(); derr != nil {
		log.Printf("[Settings] Baseline initialized but failed to compute digest: %v", derr)
		appendAdminBlock(h.ledger, actor, models.ActionBaselineInit, detail)
	} else {
		audited = appendAdminBlockWithDigest(h.ledger, actor, models.ActionBaselineInit, detail, digest, count)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "baseline initialized successfully",
		"total_files": total,
		"audited":     audited,
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
