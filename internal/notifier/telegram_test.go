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

func TestFormatAlertMessageHTMLAndSanitized(t *testing.T) {
	block := testBlock("C:\\www\\site\\functions.php\nPesan palsu", models.ActionModified, true)

	msg := formatAlertMessage(block)

	for _, want := range []string{
		"🛡️ <b>FIM-IPL · Perubahan File Terdeteksi</b>",
		"<code>BLK-000001</code>",
		"<b>MODIFIED</b> · isi file berubah",
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
}

// Nilai dinamis yang mengandung < > & harus di-escape agar tidak bisa
// menyuntikkan tag HTML ke pesan.
func TestFormatAlertMessageEscapesHTML(t *testing.T) {
	block := testBlock("/var/www/<b>jahat</b>.php", models.ActionCreated, false)
	block.QuarantineErr = "gagal: <script>alert(1)</script>"

	msg := formatAlertMessage(block)

	for _, want := range []string{
		"&lt;b&gt;jahat&lt;/b&gt;",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing escaped %q:\n%s", want, msg)
		}
	}
	for _, bad := range []string{"<b>jahat</b>", "<script>alert(1)</script>"} {
		if strings.Contains(msg, bad) {
			t.Fatalf("message must not contain raw HTML %q:\n%s", bad, msg)
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

	if !strings.Contains(msg, "<b>Total file:</b> 7") {
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
		"FIM-IPL · Perubahan Massal Terdeteksi",
		"<b>Jumlah perubahan:</b> 60 file",
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
		"Karantina Gagal pada 7 File",
		"/var/www/shella.php",
		"... dan 2 file lainnya",
		"Tindakan segera:",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("aggregated message missing %q:\n%s", want, msg)
		}
	}
}

func TestSendAlertSendsHTMLParseMode(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.Form.Get("parse_mode"); got != "HTML" {
			t.Errorf("parse_mode = %q, want HTML", got)
		}
		if got := r.Form.Get("disable_web_page_preview"); got != "true" {
			t.Errorf("disable_web_page_preview = %q", got)
		}
		if !strings.Contains(r.Form.Get("text"), "Perubahan File Terdeteksi") {
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
		if !strings.Contains(text, "Tes Notifikasi") {
			t.Errorf("unexpected test text: %q", text)
		}
		if !strings.Contains(text, "Chat ID:</b> <code>12345</code>") {
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
		"<b>UNREADABLE</b> · file tidak dapat dipindai",
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
		"FIM-IPL · PEMINDAIAN GAGAL",
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

func TestFormatAlertMessageQuarantineBreachIsUrgent(t *testing.T) {
	block := testBlock("/var/www/html/wp-config.php", models.ActionQuarantineBreach, true)
	block.OldMode = 0
	block.NewMode = 0o644
	block.OldHash = strings.Repeat("c", 64)
	block.NewHash = strings.Repeat("c", 64)

	msg := formatAlertMessage(block)

	for _, want := range []string{
		"🚨 <b>URGENT · FIM-IPL · Karantina Dibatalkan</b>",
		"<b>QUARANTINE_BREACH</b> · karantina dibatalkan pemilik berkas",
		"<b>Izin sebelum:</b> <code>0000</code>",
		"<b>Izin sesudah:</b> <code>0644</code>",
		"mengarantina ulang secara otomatis",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestFormatAlertMessageIncludesFullBlockHash(t *testing.T) {
	// T-06: setiap alert per-blok membawa hash blok LENGKAP sebagai
	// jangkar eksternal — bukan hanya ID blok.
	block := testBlock("/var/www/x.php", models.ActionCreated, true)
	block.ID = "BLK-000018"
	block.BlockHash = strings.Repeat("d", 64)

	msg := formatAlertMessage(block)

	if !strings.Contains(msg, "<code>BLK-000018</code>") {
		t.Fatalf("per-block alert must contain the block ID:\n%s", msg)
	}
	if !strings.Contains(msg, "<b>Block hash:</b> <code>"+strings.Repeat("d", 64)+"</code>") {
		t.Fatalf("per-block alert must contain the FULL block hash:\n%s", msg)
	}
}

func TestFormatBatchMessageIncludesBlockIDsAndHeadHash(t *testing.T) {
	// T-06: ringkasan batch mencantumkan ID + hash pendek tiap blok dan
	// head hash LENGKAP di akhir, agar pemotongan ekor terdeteksi dari
	// Telegram.
	blocks := []*models.Block{
		{ID: "BLK-000001", FilePath: "/var/www/a.php", Action: models.ActionCreated, BlockHash: strings.Repeat("a", 64), Quarantined: true},
		{ID: "BLK-000002", FilePath: "/var/www/b.php", Action: models.ActionModified, BlockHash: strings.Repeat("b", 64), Quarantined: true},
		{ID: "BLK-000003", FilePath: "/var/www/c.php", Action: models.ActionDeleted, BlockHash: strings.Repeat("c", 64)},
		{ID: "BLK-000004", FilePath: "/var/www/d.php", Action: models.ActionCreated, BlockHash: strings.Repeat("d", 64), Quarantined: true},
	}

	msg := formatBatchMessage(blocks, 4)

	for _, id := range []string{"BLK-000001", "BLK-000002", "BLK-000003", "BLK-000004"} {
		if !strings.Contains(msg, id) {
			t.Fatalf("batch alert must list block ID %s:\n%s", id, msg)
		}
	}
	if !strings.Contains(msg, "<b>Block terakhir:</b> <code>BLK-000004</code>") {
		t.Fatalf("batch alert must name the head block:\n%s", msg)
	}
	if !strings.Contains(msg, "<b>Hash rantai:</b> <code>"+strings.Repeat("d", 64)+"</code>") {
		t.Fatalf("batch alert must contain the FULL head hash:\n%s", msg)
	}

	bulk := formatBulkWarningMessage(60, blocks)
	if !strings.Contains(bulk, "<b>Block terakhir:</b> <code>BLK-000004</code>") || !strings.Contains(bulk, strings.Repeat("d", 64)) {
		t.Fatalf("bulk alert must contain the head block ID and full head hash:\n%s", bulk)
	}
}

// Bila Telegram menolak format HTML (400), pesan dikirim ulang sekali
// sebagai teks biasa tanpa parse_mode dan tetap terkirim.
func TestSendFallsBackToPlainTextOnBadRequest(t *testing.T) {
	var modes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		modes = append(modes, r.Form.Get("parse_mode"))
		if r.Form.Get("parse_mode") == "HTML" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: can't parse entities"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tg := NewTelegram("test-token", "12345")
	tg.apiBase = srv.URL
	if err := tg.SendAlert(testBlock("/var/www/a.php", models.ActionModified, true)); err != nil {
		t.Fatalf("SendAlert should succeed after plain-text fallback: %v", err)
	}
	if len(modes) != 2 || modes[0] != "HTML" || modes[1] != "" {
		t.Fatalf("expected HTML attempt then plain-text retry, got %v", modes)
	}
}
