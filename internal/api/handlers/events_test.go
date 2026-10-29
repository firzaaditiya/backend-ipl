package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

func TestEventsStreamBroadcasts(t *testing.T) {
	hub := realtime.NewHub()
	defer hub.Close()
	sc := scanner.New(1, []string{t.TempDir()})
	h := NewEventsHandler(hub, sc)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.Stream(rec, req)
		close(done)
	}()

	// Tunggu handler terdaftar sebagai subscriber.
	deadline := time.Now().Add(time.Second)
	for hub.Subscribers() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("handler did not subscribe in time")
		}
		time.Sleep(5 * time.Millisecond)
	}

	hub.Publish("scan", map[string]int{"anomalies": 1})
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream handler did not exit after context cancel")
	}

	body := rec.Body.String()
	if !strings.HasPrefix(body, "event: hello") {
		t.Fatalf("expected hello event first, got: %q", body)
	}
	if !strings.Contains(body, "event: scan") || !strings.Contains(body, `"anomalies":1`) {
		t.Fatalf("expected broadcast event in stream, got: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}
}

func TestEventsStreamRejectsNonGet(t *testing.T) {
	h := NewEventsHandler(realtime.NewHub(), scanner.New(1, nil))
	rec := httptest.NewRecorder()
	h.Stream(rec, httptest.NewRequest(http.MethodPost, "/api/v1/events", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestEventsHandlerPerIPLimit(t *testing.T) {
	h := NewEventsHandler(realtime.NewHub(), scanner.New(1, nil))
	ip := "203.0.113.9"

	for i := 0; i < sseMaxPerIP; i++ {
		if !h.acquire(ip) {
			t.Fatalf("expected acquire %d to succeed", i+1)
		}
	}
	if h.acquire(ip) {
		t.Fatal("expected per-IP limit to reject additional streams")
	}

	// Klien lain tetap boleh membuka stream.
	if !h.acquire("198.51.100.7") {
		t.Fatal("expected a different client to be allowed")
	}

	// Slot kembali tersedia setelah stream ditutup.
	h.release(ip)
	if !h.acquire(ip) {
		t.Fatal("expected slot to be reusable after release")
	}
}
