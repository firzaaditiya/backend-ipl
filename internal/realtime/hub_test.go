package realtime

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPublishDeliversToSubscriber(t *testing.T) {
	hub := NewHub()
	events, cancel := hub.Subscribe()
	defer cancel()

	hub.Publish("scan", map[string]interface{}{"anomalies": 2})

	select {
	case ev := <-events:
		if ev.Type != "scan" {
			t.Fatalf("expected type scan, got %s", ev.Type)
		}
		var data struct {
			Anomalies int `json:"anomalies"`
		}
		if err := json.Unmarshal(ev.Data, &data); err != nil {
			t.Fatalf("decode data: %v", err)
		}
		if data.Anomalies != 2 {
			t.Fatalf("expected anomalies=2, got %d", data.Anomalies)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestPublishDropsWhenSubscriberFull(t *testing.T) {
	hub := NewHub()
	_, cancel := hub.Subscribe()
	defer cancel()

	// Isi buffer + lebih; tidak boleh deadlock.
	done := make(chan struct{})
	go func() {
		for i := 0; i < subscriberBuffer*4; i++ {
			hub.Publish("scan", map[string]int{"i": i})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
}

func TestCancelRemovesSubscriber(t *testing.T) {
	hub := NewHub()
	_, cancel := hub.Subscribe()
	if hub.Subscribers() != 1 {
		t.Fatalf("expected 1 subscriber, got %d", hub.Subscribers())
	}
	cancel()
	cancel() // idempotent
	if hub.Subscribers() != 0 {
		t.Fatalf("expected 0 subscribers after cancel, got %d", hub.Subscribers())
	}
}

func TestCloseEndsSubscribers(t *testing.T) {
	hub := NewHub()
	events, _ := hub.Subscribe()
	hub.Close()

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("expected closed channel after hub.Close")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}
