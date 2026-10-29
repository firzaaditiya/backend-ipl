package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

const (
	sseHeartbeat      = 15 * time.Second
	sseMaxSubscribers = 64
	// sseMaxPerIP mencegah satu klien membuka seluruh kuota stream.
	sseMaxPerIP = 4
)

// EventsHandler menyajikan stream Server-Sent Events untuk pembaruan
// dashboard secara realtime. Autentikasi tetap memakai bearer token karena
// klien membaca stream lewat fetch(), bukan EventSource bawaan browser.
type EventsHandler struct {
	hub     *realtime.Hub
	scanner *scanner.Scanner

	mu    sync.Mutex
	perIP map[string]int
}

func NewEventsHandler(hub *realtime.Hub, s *scanner.Scanner) *EventsHandler {
	return &EventsHandler{
		hub:     hub,
		scanner: s,
		perIP:   make(map[string]int),
	}
}

func (h *EventsHandler) acquire(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.perIP[ip] >= sseMaxPerIP {
		return false
	}
	h.perIP[ip]++
	return true
}

func (h *EventsHandler) release(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.perIP[ip] <= 1 {
		delete(h.perIP, ip)
		return
	}
	h.perIP[ip]--
}

func (h *EventsHandler) Stream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
		return
	}

	if h.hub.Subscribers() >= sseMaxSubscribers {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many event streams"})
		return
	}

	ip := middleware.ClientIP(r)
	if !h.acquire(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many event streams for this client"})
		return
	}
	defer h.release(ip)

	// Stream berumur panjang: matikan write deadline untuk koneksi ini saja.
	// Tanpa ini, WriteTimeout server (30 dtk) akan memutus koneksi.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, cancel := h.hub.Subscribe()
	defer cancel()

	// hello dikirim setelah subscribe agar jumlah subscriber akurat.
	writeSSE(w, flusher, "hello", map[string]interface{}{
		"is_monitoring":    h.scanner.IsRunning(),
		"maintenance_mode": h.scanner.IsMaintenance(),
		"subscribers":      h.hub.Subscribers(),
	})

	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			writeSSE(w, flusher, ev.Type, ev)
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, eventType string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, data); err != nil {
		return
	}
	flusher.Flush()
}
