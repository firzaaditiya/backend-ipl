package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

type DashboardHandler struct {
	ledger  *ledger.Ledger
	scanner *scanner.Scanner
}

func NewDashboardHandler(l *ledger.Ledger, s *scanner.Scanner) *DashboardHandler {
	return &DashboardHandler{
		ledger:  l,
		scanner: s,
	}
}

func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	counts, err := h.ledger.GetDashboardCounts()
	if err != nil {
		http.Error(w, `{"error":"failed to read dashboard counts"}`, http.StatusInternalServerError)
		return
	}

	safeFiles := counts.TotalFiles - counts.QuarantinedFiles
	if safeFiles < 0 {
		safeFiles = 0
	}

	stats := map[string]interface{}{
		"total_files":       counts.TotalFiles,
		"safe_files":        safeFiles,
		"quarantined_files": counts.QuarantinedFiles,
		"total_anomalies":   counts.Anomalies,
		"total_blocks":      counts.TotalBlocks,
		"is_monitoring":     h.scanner.IsRunning(),
		"maintenance_mode":  h.scanner.IsMaintenance(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *DashboardHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"is_monitoring":    h.scanner.IsRunning(),
		"maintenance_mode": h.scanner.IsMaintenance(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
