package backup

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/ledger"
)

func newTestLedger(t *testing.T) *ledger.Ledger {
	t.Helper()
	l, err := ledger.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("ledger.New: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestFormatCaptionIncludesHeadAnchor(t *testing.T) {
	exp := &ledger.LedgerExport{
		GeneratedAt: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		TotalBlocks: 12,
		HeadHash:    strings.Repeat("f", 64),
		Verify:      ledger.VerifyResult{Valid: true},
	}

	caption := formatCaption("manual", "fim-ipl-ledger-manual-1.json", exp)

	for _, want := range []string{
		"FIM-IPL: BACKUP LEDGER",
		"Jenis       : manual",
		"Total blok  : 12",
		"Verifikasi  : UTUH",
		"Head hash   : " + strings.Repeat("f", 64),
		"fim-ipl-ledger-manual-1.json",
	} {
		if !strings.Contains(caption, want) {
			t.Fatalf("caption missing %q:\n%s", want, caption)
		}
	}
}

func TestSanitizeLabelPreventsPathTraversal(t *testing.T) {
	if got := sanitizeLabel("../../etc/passwd"); got != "etc-passwd" {
		t.Fatalf("sanitizeLabel = %q, want %q", got, "etc-passwd")
	}
	if got := sanitizeLabel("   "); got != "manual" {
		t.Fatalf("empty label = %q, want manual", got)
	}
}

func TestRunOnceRequiresChannel(t *testing.T) {
	m := NewManager(newTestLedger(t), nil, "", time.Hour)

	err := m.RunOnce("manual")
	if err == nil || !strings.Contains(err.Error(), "no backup channel configured") {
		t.Fatalf("expected no-channel error, got %v", err)
	}
}

func TestStopWaitsForInFlightRun(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	m := NewManager(newTestLedger(t), nil, srv.URL, time.Hour)

	runErr := make(chan error, 1)
	go func() {
		runErr <- m.RunOnce("manual")
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("webhook was not called")
	}

	stopped := make(chan struct{})
	go func() {
		m.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned while backup was still in flight")
	case <-time.After(150 * time.Millisecond):
	}

	close(release)

	if err := <-runErr; err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after backup completed")
	}
}
