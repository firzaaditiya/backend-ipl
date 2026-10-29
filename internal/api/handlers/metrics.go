package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
)

type MetricsHandler struct {
	ledger *ledger.Ledger
}

func NewMetricsHandler(l *ledger.Ledger) *MetricsHandler {
	return &MetricsHandler{ledger: l}
}

// GetMetrics mengembalikan time-series metrik scan cycle (elapsed_ms, memory).
// Query params:
//   - limit=<int>   (default 100, max 1000)
func (h *MetricsHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	metrics, err := h.ledger.GetMetrics(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load metrics"})
		return
	}
	if metrics == nil {
		metrics = []models.ScanMetric{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"metrics": metrics,
		"count":   len(metrics),
	})
}
