package handlers

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

// AppVersion adalah versi aplikasi yang ditampilkan di UI dan /healthz.
const AppVersion = "1.0.0"

// SystemHandler menyajikan informasi runtime yang aman untuk ditampilkan di UI.
// Tidak ada secret, path data, atau kredensial yang dikembalikan.
type SystemHandler struct {
	cfg       *config.Config
	scanner   *scanner.Scanner
	startedAt time.Time
}

func NewSystemHandler(cfg *config.Config, s *scanner.Scanner) *SystemHandler {
	return &SystemHandler{
		cfg:       cfg,
		scanner:   s,
		startedAt: time.Now(),
	}
}

func (h *SystemHandler) GetInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	quarantineMode := "chmod_000"
	if runtime.GOOS == "windows" {
		quarantineMode = "readonly_fallback"
	}

	info := map[string]interface{}{
		"app_name":          "FIM-IPL",
		"version":           AppVersion,
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
		"go_version":        runtime.Version(),
		"started_at":        h.startedAt.UTC().Format(time.RFC3339),
		"uptime_sec":        int(time.Since(h.startedAt).Seconds()),
		"quarantine_mode":   quarantineMode,
		"watch_paths":       h.cfg.GetWatchPaths(),
		"worker_count":      h.cfg.GetWorkerCount(),
		"scan_interval_sec": h.cfg.GetScanInterval(),
		"is_monitoring":     h.scanner.IsRunning(),
		"maintenance_mode":  h.scanner.IsMaintenance(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// Health adalah liveness probe publik untuk load balancer / systemd watchdog.
// Sengaja tidak mengembalikan data konfigurasi maupun status internal.
func (h *SystemHandler) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"version": AppVersion,
		"uptime":  int(time.Since(h.startedAt).Seconds()),
	})
}
