package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
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
		"💾 <b>FIM-IPL · Backup Ledger</b>",
		"<b>Jenis:</b> manual",
		"<b>Total blok:</b> 12",
		"✅ UTUH",
		"<b>Head hash:</b> <code>" + strings.Repeat("f", 64) + "</code>",
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

func TestPostWebhookRejectsInternalAddress(t *testing.T) {
	m := NewManager(newTestLedger(t), nil, "", time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("internal webhook target must not be contacted")
	}))
	defer srv.Close()

	if err := m.postWebhook(srv.URL+"/hook", "test.json", []byte("{}")); err == nil {
		t.Fatal("expected webhook to 127.0.0.1 to be refused")
	}
}

func TestPostWebhookRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("redirect target must not be contacted")
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/hook")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	m := NewManager(newTestLedger(t), nil, "", time.Hour)
	// Izinkan localhost hanya agar redirect-nya teramati, dan pakai client
	// tanpa dial guard agar yang diuji murni perilaku redirect (produksi
	// memakai keduanya: dial guard + penolakan redirect).
	m.allowLocalWebhook = true
	m.httpClient = &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if err := m.postWebhook(redirector.URL+"/hook", "test.json", []byte("{}")); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
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
	// httptest berjalan di 127.0.0.1; izinkan hanya untuk test ini.
	m.allowLocalWebhook = true

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

func TestPostWebhookSignsWithHMAC(t *testing.T) {
	var gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-FIM-IPL-Signature")
		gotTS = r.Header.Get("X-FIM-IPL-Timestamp")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager(newTestLedger(t), nil, "", time.Hour)
	m.allowLocalWebhook = true
	m.SetWebhookSecret("test-secret")
	payload := []byte(`{"blocks":1}`)

	if err := m.postWebhook(srv.URL+"/hook", "test.json", payload); err != nil {
		t.Fatalf("postWebhook: %v", err)
	}
	if gotSig == "" || gotTS == "" {
		t.Fatalf("expected signature headers, got sig=%q ts=%q", gotSig, gotTS)
	}
	ts, err := strconv.ParseInt(gotTS, 10, 64)
	if err != nil || time.Now().Unix()-ts > 60 || ts > time.Now().Unix()+5 {
		t.Fatalf("timestamp must be current unix time, got %q", gotTS)
	}
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write([]byte(gotTS + "."))
	mac.Write(payload)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature mismatch: got %q want %q", gotSig, want)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body changed by signing: got %q", gotBody)
	}
}

func TestPostWebhookNoSignatureWithoutSecret(t *testing.T) {
	var gotSig, gotTS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-FIM-IPL-Signature")
		gotTS = r.Header.Get("X-FIM-IPL-Timestamp")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager(newTestLedger(t), nil, "", time.Hour)
	m.allowLocalWebhook = true
	// Tanpa SetWebhookSecret: tidak ada header tanda tangan.
	if err := m.postWebhook(srv.URL+"/hook", "test.json", []byte(`{}`)); err != nil {
		t.Fatalf("postWebhook: %v", err)
	}
	if gotSig != "" || gotTS != "" {
		t.Fatalf("expected no signature headers without secret, got sig=%q ts=%q", gotSig, gotTS)
	}
}

func TestGuardedDialRefusesLocalhostName(t *testing.T) {
	// "localhost" resolve ke 127.0.0.1 — dial guard harus menolaknya walau
	// host-nya berupa nama, bukan IP literal.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := guardedDialContext(ctx, "tcp", "localhost:9"); err == nil {
		t.Fatal("expected dial to localhost to be refused")
	}
	if _, err := guardedDialContext(ctx, "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("expected dial to 127.0.0.1 to be refused")
	}
}
