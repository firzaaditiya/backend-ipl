package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/skripsi/fim-ipl/internal/ledger"
)

type LedgerHandler struct {
	ledger *ledger.Ledger
}

func NewLedgerHandler(l *ledger.Ledger) *LedgerHandler {
	return &LedgerHandler{ledger: l}
}

func (h *LedgerHandler) GetBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	search := query.Get("search")
	action := query.Get("action")

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	offset := (page - 1) * limit

	var response map[string]interface{}

	if search != "" || action != "" {
		blocks, total, err := h.ledger.SearchBlocks(search, action, offset, limit)
		if err != nil {
			http.Error(w, `{"error":"failed to search blocks"}`, http.StatusInternalServerError)
			return
		}
		response = map[string]interface{}{
			"blocks":      blocks,
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + limit - 1) / limit,
		}
	} else {
		blocks, total, err := h.ledger.GetBlocks(offset, limit)
		if err != nil {
			http.Error(w, `{"error":"failed to get blocks"}`, http.StatusInternalServerError)
			return
		}
		response = map[string]interface{}{
			"blocks":      blocks,
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + limit - 1) / limit,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *LedgerHandler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	res := h.ledger.VerifyChain()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// ExportLedger mengirim seluruh isi ledger dalam bentuk JSON (attachment).
// Cocok untuk arsip / audit / laporan skripsi.
func (h *LedgerHandler) ExportLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	exp, err := h.ledger.ExportAll(true)
	if err != nil {
		http.Error(w, `{"error":"failed to export ledger"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="fim-ipl-ledger-export.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(exp)
}
