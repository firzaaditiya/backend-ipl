// Package realtime menyediakan hub broadcast in-process untuk Server-Sent
// Events (SSE). Hub sengaja dibuat sederhana: subscriber yang lambat akan
// kehilangan event (non-blocking send) agar satu klien tidak memperlambat
// seluruh sistem.
package realtime

import (
	"encoding/json"
	"sync"
	"time"
)

// Event adalah satu kejadian yang dikirim ke klien SSE.
type Event struct {
	Type string          `json:"type"`
	At   time.Time       `json:"at"`
	Data json.RawMessage `json:"data,omitempty"`
}

const subscriberBuffer = 32

// Hub menyimpan daftar subscriber aktif.
type Hub struct {
	mu     sync.RWMutex
	subs   map[int]chan Event
	nextID int
	closed bool
}

func NewHub() *Hub {
	return &Hub{subs: make(map[int]chan Event)}
}

// Subscribe mendaftarkan subscriber baru. cancel() wajib dipanggil saat
// koneksi berakhir agar channel tidak bocor.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}

	id := h.nextID
	h.nextID++
	ch := make(chan Event, subscriberBuffer)
	h.subs[id] = ch

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if existing, ok := h.subs[id]; ok {
				delete(h.subs, id)
				close(existing)
			}
		})
	}
	return ch, cancel
}

// Publish menyiarkan event ke semua subscriber. Data di-marshal ke JSON.
// Jika antrean subscriber penuh, event untuk subscriber tersebut dibuang.
func (h *Hub) Publish(eventType string, data interface{}) {
	ev := Event{Type: eventType, At: time.Now().UTC()}
	if data != nil {
		if raw, err := json.Marshal(data); err == nil {
			ev.Data = raw
		}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribers mengembalikan jumlah koneksi SSE aktif.
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Close menghentikan seluruh subscriber (dipakai saat shutdown).
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, ch := range h.subs {
		delete(h.subs, id)
		close(ch)
	}
}
