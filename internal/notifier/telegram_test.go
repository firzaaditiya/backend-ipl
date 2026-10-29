package notifier

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
)

func testBlock(path, action string, quarantined bool) *models.Block {
	return &models.Block{
		ID:            "BLK-000001",
		Timestamp:     time.Date(2026, 10, 23, 14, 35, 52, 0, time.UTC),
		FilePath:      path,
		Action:        action,
		OldHash:       strings.Repeat("a", 64),
		NewHash:       strings.Repeat("b", 64),
		Quarantined:   quarantined,
		QuarantineErr: "",
	}
}

func TestFormatAlertMessagePlainTextAndSanitized(t *testing.T) {
	block := testBlock("C:\\www\\site\\functions.php\nPesan palsu", models.ActionModified, true)

	msg := formatAlertMessage(block)

	for _, want := range []string{
		"FIM-IPL: PERUBAHAN FILE TERDETEKSI",
		"Block        : BLK-000001",
		"MODIFIED (isi file berubah)",
		"C:\\www\\site\\functions.php Pesan palsu",
		"Berhasil dikarantina",
		"aaaaaaaa...aaaaaaaa",
		"Tindakan yang disarankan:",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "\nPesan palsu") {
		t.Fatal("newline in file path must not create a new message line")
	}
	for _, r := range msg {
		if r > 127 {
			t.Fatalf("message must not contain emoji/non-ASCII characters: %q", msg)
		}
	}
}

func TestFormatAlertMessageQuarantineFailure(t *testing.T) {
	block := testBlock("/var/www/shell.php", models.ActionCreated, false)
	block.QuarantineErr = "permission denied"

	msg := formatAlertMessage(block)

	if !strings.Contains(msg, "GAGAL dikarantina: permission denied") {
		t.Fatalf("missing failure status:\n%s", msg)
	}
	if !strings.Contains(msg, "pindahkan file secara manual") {
		t.Fatalf("missing urgent recommendation:\n%s", msg)
	}
}

func TestFormatBatchMessageListsAtMostFiveFiles(t *testing.T) {
	var blocks []*models.Block
	for i := 0; i < 7; i++ {
		blocks = append(blocks, testBlock("/var/www/file"+string(rune('a'+i))+".php", models.ActionCreated, true))
	}

	msg := formatBatchMessage(blocks, len(blocks))

	if !strings.Contains(msg, "Total file : 7") {
		t.Fatalf("missing total:\n%s", msg)
	}
	if !strings.Contains(msg, "... dan 2 file lainnya.") {
		t.Fatalf("missing truncation note:\n%s", msg)
	}
}

func TestFormatBulkWarningIncludesBreakdown(t *testing.T) {
	blocks := []*models.Block{
		testBlock("/a.php", models.ActionModified, true),
		testBlock("/b.php", models.ActionCreated, true),
		testBlock("/c.php", models.ActionDeleted, false),
		testBlock("/d.php", models.ActionUnreadable, false),
	}

	msg := formatBulkWarningMessage(60, blocks)

	for _, want := range []string{
		"FIM-IPL: PERUBAHAN MASSAL TERDETEKSI",
		"Jumlah perubahan : 60 file",
		"1 modified, 1 created, 1 deleted, 1 unreadable",
		"Update CMS, plugin, atau tema WordPress",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("bulk message missing %q:\n%s", want, msg)
		}
	}
}

func TestSendQuarantineFailuresAggregates(t *testing.T) {
	messages := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		messages <- r.Form.Get("text")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL

	failures := make([]QuarantineFailure, 7)
	for i := range failures {
		failures[i] = QuarantineFailure{
			FilePath: "/var/www/shell" + string(rune('a'+i)) + ".php",
			Reason:   "permission denied",
		}
	}

	if err := tg.SendQuarantineFailures(failures); err != nil {
		t.Fatalf("SendQuarantineFailures: %v", err)
	}

	var msg string
	select {
	case msg = <-messages:
	default:
		t.Fatal("expected one aggregated message, got none")
	}
	for _, want := range []string{
		"KARANTINA GAGAL PADA 7 FILE",
		"/var/www/shella.php",
		"... dan 2 file lainnya",
		"Tindakan segera:",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("aggregated message missing %q:\n%s", want, msg)
		}
	}
}

func TestSendAlertSendsEveryTimeWithoutParseMode(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.Form.Get("parse_mode"); got != "" {
			t.Errorf("parse_mode must be empty, got %q", got)
		}
		if got := r.Form.Get("disable_web_page_preview"); got != "true" {
			t.Errorf("disable_web_page_preview = %q", got)
		}
		if !strings.Contains(r.Form.Get("text"), "PERUBAHAN FILE TERDETEKSI") {
			t.Errorf("unexpected message text: %q", r.Form.Get("text"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL
	block := testBlock("/var/www/a.php", models.ActionModified, true)

	if err := tg.SendAlert(block); err != nil {
		t.Fatalf("first SendAlert: %v", err)
	}
	if err := tg.SendAlert(block); err != nil {
		t.Fatalf("second SendAlert: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected both alerts to be delivered, got %d calls", got)
	}
}

func TestSendAlertRedactsTokenFromNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := srv.URL
	srv.Close()

	tg := NewTelegram("SECRET-TOKEN", "12345")
	tg.apiBase = endpoint

	err := tg.SendAlert(testBlock("/var/www/a.php", models.ActionModified, true))
	if err == nil {
		t.Fatal("expected network error")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("token leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "<token>") {
		t.Fatalf("expected redacted token marker, got: %v", err)
	}
}

func TestSendTestMessageContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		text := r.Form.Get("text")
		if !strings.Contains(text, "FIM-IPL: TES NOTIFIKASI") {
			t.Errorf("unexpected test text: %q", text)
		}
		if !strings.Contains(text, "Chat ID      : 12345") {
			t.Errorf("chat id missing from test text: %q", text)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL
	if err := tg.SendTestMessage(); err != nil {
		t.Fatalf("SendTestMessage: %v", err)
	}
}

func TestFormatUnreadableAlert(t *testing.T) {
	block := &models.Block{
		ID:            "BLK-000010",
		Timestamp:     time.Now(),
		FilePath:      "/var/www/html/wp-content/uploads/backdoor.php",
		Action:        models.ActionUnreadable,
		OldHash:       strings.Repeat("a", 64),
		Quarantined:   true,
		QuarantineErr: "pemindaian: permission denied",
	}

	msg := formatAlertMessage(block)

	for _, want := range []string{
		"UNREADABLE (file tidak dapat dipindai)",
		"Tidak dapat dipindai: pemindaian: permission denied",
		"Periksa izin file/folder",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("unreadable alert missing %q:\n%s", want, msg)
		}
	}
}

func TestSendSystemAlert(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.Store(r.Form.Get("text"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL
	if err := tg.SendSystemAlert("PEMINDAIAN GAGAL", "watch path tidak ditemukan"); err != nil {
		t.Fatalf("SendSystemAlert: %v", err)
	}

	text, _ := got.Load().(string)
	for _, want := range []string{
		"FIM-IPL: PEMINDAIAN GAGAL",
		"watch path tidak ditemukan",
		"Pastikan watch path ada",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("system alert missing %q:\n%s", want, text)
		}
	}
}

func TestSendRetriesTransientFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL
	if err := tg.sendMessage("tes retry"); err != nil {
		t.Fatalf("sendMessage harus berhasil setelah retry: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

func TestSendDoesNotRetryPermanentFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL
	if err := tg.sendMessage("tes permanen"); err == nil {
		t.Fatal("expected error for 401")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("kesalahan permanen tidak boleh diulang, got %d attempts", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	body := []byte(`{"ok":false,"error_code":429,"parameters":{"retry_after":3}}`)
	if got := parseRetryAfter(body); got != 3*time.Second {
		t.Fatalf("retry_after = %v, want 3s", got)
	}
	if got := parseRetryAfter([]byte(`not json`)); got != 0 {
		t.Fatalf("invalid body should yield 0, got %v", got)
	}
}
