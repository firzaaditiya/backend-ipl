package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
)

const (
	// BulkThreshold adalah jumlah anomali dalam satu siklus yang dianggap
	// sebagai perubahan massal (mis. update CMS/plugin).
	BulkThreshold = 50

	defaultAPIBase = "https://api.telegram.org"
	maxListedFiles = 5
)

// Telegram adalah klien Bot API untuk notifikasi operasional.
//
// Pesan dikirim sebagai HTML (parse_mode=HTML) dengan emoji hanya pada
// judul pesan: judul tebal, nilai (path, hash, ID) dalam <code>. Semua nilai
// dinamis di-escape (esc) agar karakter < > & dari nama file atau alasan
// tidak bisa merusak format atau menyuntikkan tag. Bila Telegram menolak
// format HTML (400), pesan dikirim ulang sekali sebagai teks biasa.
type Telegram struct {
	mu        sync.RWMutex
	token     string
	chatID    string
	client    *http.Client
	docClient *http.Client
	apiBase   string
}

func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 15 * time.Second},
		docClient: &http.Client{
			Timeout: 45 * time.Second,
		},
		apiBase: defaultAPIBase,
	}
}

func (t *Telegram) UpdateConfig(token, chatID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = token
	t.chatID = chatID
}

func (t *Telegram) IsConfigured() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.token != "" && t.chatID != ""
}

func (t *Telegram) getCredentials() (string, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.token, t.chatID
}

// SendAlert mengirim satu notifikasi untuk satu anomali. Tidak ada cooldown:
// setiap anomali baru memang harus terlihat oleh admin. Duplikasi dicegah oleh
// pembaruan baseline otomatis setelah anomali dicatat.
func (t *Telegram) SendAlert(block *models.Block) error {
	if !t.IsConfigured() {
		log.Println("[Telegram] Skipped: token or chat_id not configured")
		return nil
	}
	if block == nil {
		return nil
	}
	return t.sendMessage(formatAlertMessage(block))
}

// SendBatchAlert mengirim ringkasan untuk beberapa anomali dalam satu siklus.
// Untuk perubahan massal (>= BulkThreshold), pesan dibuat lebih ringkas agar
// admin tidak dibanjiri daftar file.
func (t *Telegram) SendBatchAlert(blocks []*models.Block, totalAnomalies int) error {
	if !t.IsConfigured() {
		return nil
	}
	if len(blocks) == 0 {
		return nil
	}

	var message string
	if totalAnomalies >= BulkThreshold {
		message = formatBulkWarningMessage(totalAnomalies, blocks)
	} else {
		message = formatBatchMessage(blocks, totalAnomalies)
	}
	return t.sendMessage(message)
}

func (t *Telegram) SendTestMessage() error {
	if !t.IsConfigured() {
		return fmt.Errorf("telegram token or chat_id not configured")
	}
	_, chatID := t.getCredentials()

	msg := fmt.Sprintf(
		"✅ <b>FIM-IPL · Tes Notifikasi</b>\n\n"+
			"Konfigurasi Telegram berhasil.\n\n"+
			"<b>Waktu server:</b> %s\n"+
			"<b>Chat ID:</b> <code>%s</code>\n\n"+
			"Pesan ini berasal dari tombol uji di halaman Pengaturan. "+
			"Tidak ada perubahan file yang terkait dengan pesan ini.",
		formatTimestamp(time.Now()), esc(chatID),
	)
	return t.sendMessage(msg)
}

// SendSystemAlert mengirim kegagalan operasional (mis. watch path hilang atau
// rantai ledger rusak) yang membuat pemindaian tidak berjalan atau bukti
// tidak lagi dapat dipercaya. Tanpa ini, kegagalan hanya terlihat di log
// server dan admin tidak mendapat peringatan.
func (t *Telegram) SendSystemAlert(title, detail string) error {
	if !t.IsConfigured() {
		return fmt.Errorf("telegram token or chat_id not configured")
	}

	var b strings.Builder
	if title == "RANTAI LEDGER RUSAK" {
		b.WriteString("🚨 <b>URGENT · FIM-IPL · Rantai Ledger Rusak</b>\n\n")
	} else {
		fmt.Fprintf(&b, "⚠️ <b>FIM-IPL · %s</b>\n\n", esc(title))
	}
	fmt.Fprintf(&b, "<b>Waktu:</b> %s\n", esc(formatTimestamp(time.Now())))
	fmt.Fprintf(&b, "<b>Masalah:</b> %s\n", esc(detail))
	if title == "RANTAI LEDGER RUSAK" {
		b.WriteString("\n<b>Tindakan:</b>\n")
		b.WriteString("1. Bandingkan head hash di pesan ini dengan head hash di dashboard. Bila berbeda, rantai di server sudah diubah.\n")
		b.WriteString("2. Jangan jalankan baseline/update sebelum penyebabnya jelas.\n")
		b.WriteString("3. Pulihkan ledger dari backup terakhir bila perlu, lalu audit akun dan log akses server.\n")
	} else {
		b.WriteString("\n<b>Tindakan:</b>\n")
		b.WriteString("1. Pastikan watch path ada dan dapat dibaca oleh akun service FIM.\n")
		b.WriteString("2. Periksa izin folder serta ruang disk.\n")
		b.WriteString("3. Setelah diperbaiki, jalankan baseline ulang bila struktur file berubah.\n")
	}
	return t.sendMessage(b.String())
}

// Kebijakan retry untuk pesan teks. Hanya kegagalan sementara yang diulang
// (error jaringan, 429, 5xx). Kesalahan permanen (token salah, chat tidak
// ditemukan) langsung dikembalikan agar admin melihat penyebab yang jelas.
const (
	sendMaxAttempts = 3
	sendBaseBackoff = 1 * time.Second
	sendMaxBackoff  = 10 * time.Second
)

// sendRetryable menandai error yang layak diulang; retryAfter berasal dari
// header/body Telegram (429) dan dibatasi sendMaxBackoff.
type sendRetryable struct {
	err        error
	retryAfter time.Duration
}

func (e *sendRetryable) Error() string { return e.err.Error() }

// badRequestError menandai penolakan 400 dari Telegram — dipakai untuk memicu
// pengiriman ulang sebagai teks biasa (tanpa parse_mode HTML).
type badRequestError struct{ err error }

func (e *badRequestError) Error() string { return e.err.Error() }

// sendMessage mengirim pesan sebagai HTML; bila Telegram menolak formatnya
// (400), pesan dikirim ulang sekali sebagai teks biasa agar tidak ada alert
// yang hilang gara-gara format.
func (t *Telegram) sendMessage(text string) error {
	err := t.sendWithRetries(text, "HTML")
	if err != nil {
		var badReq *badRequestError
		if errors.As(err, &badReq) {
			log.Printf("[Telegram] Format HTML ditolak (%v); kirim ulang sebagai teks biasa", badReq.err)
			return t.sendWithRetries(stripHTMLTags(text), "")
		}
	}
	return err
}

func (t *Telegram) sendWithRetries(text, parseMode string) error {
	var lastErr error
	for attempt := 1; attempt <= sendMaxAttempts; attempt++ {
		err := t.sendMessageOnce(text, parseMode)
		if err == nil {
			if attempt > 1 {
				log.Printf("[Telegram] Pesan terkirim pada percobaan ke-%d", attempt)
			}
			return nil
		}
		lastErr = err

		retry, ok := err.(*sendRetryable)
		if !ok || attempt == sendMaxAttempts {
			break
		}
		wait := sendBaseBackoff << (attempt - 1)
		if retry.retryAfter > wait {
			wait = retry.retryAfter
		}
		if wait > sendMaxBackoff {
			wait = sendMaxBackoff
		}
		log.Printf("[Telegram] Percobaan %d gagal (%v); ulang dalam %s", attempt, retry.err, wait)
		time.Sleep(wait)
	}
	return lastErr
}

func (t *Telegram) sendMessageOnce(text, parseMode string) error {
	token, chatID := t.getCredentials()

	params := url.Values{}
	params.Set("chat_id", chatID)
	params.Set("text", text)
	if parseMode != "" {
		params.Set("parse_mode", parseMode)
	}
	params.Set("disable_web_page_preview", "true")

	endpoint := t.endpoint(token, "sendMessage")
	resp, err := t.client.Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	if err != nil {
		return &sendRetryable{err: fmt.Errorf("telegram API request failed: %s", redactToken(err.Error(), token))}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		apiErr := fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, redactToken(strings.TrimSpace(string(body)), token))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return &sendRetryable{err: apiErr, retryAfter: parseRetryAfter(body)}
		}
		if resp.StatusCode == http.StatusBadRequest {
			return &badRequestError{err: apiErr}
		}
		return apiErr
	}

	// Body wajib dibaca sampai habis agar koneksi HTTP dapat dipakai ulang.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	log.Println("[Telegram] Notification sent successfully")
	return nil
}

// parseRetryAfter membaca parameters.retry_after dari respons 429 Telegram.
func parseRetryAfter(body []byte) time.Duration {
	var payload struct {
		Parameters struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Parameters.RetryAfter <= 0 {
		return 0
	}
	return time.Duration(payload.Parameters.RetryAfter) * time.Second
}

// QuarantineFailure merinci satu file yang gagal dinonaktifkan.
type QuarantineFailure struct {
	FilePath string
	Reason   string
}

// SendQuarantineFailure mengirim peringatan prioritas tinggi ketika file
// mencurigakan gagal dinonaktifkan. Pesan ini tidak pernah ditahan cooldown
// karena file berbahaya masih dapat diakses.
func (t *Telegram) SendQuarantineFailure(filePath, reason string) error {
	return t.SendQuarantineFailures([]QuarantineFailure{{FilePath: filePath, Reason: reason}})
}

// SendQuarantineFailures mengirim satu pesan untuk semua kegagalan karantina
// dalam satu siklus. Penggabungan mencegah puluhan pesan terpisah saat terjadi
// perubahan massal, tanpa menyembunyikan kegagalan apa pun.
func (t *Telegram) SendQuarantineFailures(failures []QuarantineFailure) error {
	if !t.IsConfigured() || len(failures) == 0 {
		return nil
	}

	var b strings.Builder
	if len(failures) == 1 {
		b.WriteString("❌ <b>FIM-IPL · Karantina Gagal · Tindakan Diperlukan</b>\n\n")
		fmt.Fprintf(&b, "<b>Waktu:</b> %s\n", esc(formatTimestamp(time.Now())))
		fmt.Fprintf(&b, "<b>File:</b> <code>%s</code>\n", esc(failures[0].FilePath))
		fmt.Fprintf(&b, "<b>Alasan:</b> %s\n", esc(failures[0].Reason))
	} else {
		fmt.Fprintf(&b, "❌ <b>FIM-IPL · Karantina Gagal pada %d File</b>\n\n", len(failures))
		fmt.Fprintf(&b, "<b>Waktu:</b> %s\n\n", esc(formatTimestamp(time.Now())))
		b.WriteString("<b>File yang gagal dinonaktifkan:</b>\n")
		listed := 0
		for _, failure := range failures {
			if listed >= maxListedFiles {
				break
			}
			listed++
			fmt.Fprintf(&b, "%d. <code>%s</code>\n   Alasan: %s\n", listed, esc(failure.FilePath), esc(failure.Reason))
		}
		if remaining := len(failures) - listed; remaining > 0 {
			fmt.Fprintf(&b, "... dan %d file lainnya. Lihat Audit Trail untuk daftar lengkap.\n", remaining)
		}
	}

	if len(failures) == 1 {
		b.WriteString("\nFile tersebut masih dapat diakses melalui web server.\n\n")
	} else {
		b.WriteString("\nFile-file tersebut masih dapat diakses melalui web server.\n\n")
	}
	b.WriteString("<b>Tindakan segera:</b>\n")
	b.WriteString("1. Nonaktifkan akses ke file melalui firewall, WAF, atau pindahkan file secara manual.\n")
	b.WriteString("2. Periksa isi file dan log akses web server.\n")
	b.WriteString("3. Perbaiki izin folder, lalu jalankan karantina ulang.")
	return t.sendMessage(b.String())
}

// SendDocument mengirim file (byte slice) sebagai dokumen ke chat Telegram.
// Digunakan oleh modul backup untuk mengirim export JSON ledger. Caption
// dikirim sebagai HTML; bila ditolak (400), dikirim ulang sebagai teks biasa.
func (t *Telegram) SendDocument(filename string, data []byte, caption string) error {
	if !t.IsConfigured() {
		return fmt.Errorf("telegram not configured")
	}
	if err := t.sendDocumentOnce(filename, data, caption, "HTML"); err != nil {
		var badReq *badRequestError
		if errors.As(err, &badReq) {
			log.Printf("[Telegram] Caption HTML ditolak (%v); kirim ulang sebagai teks biasa", badReq.err)
			return t.sendDocumentOnce(filename, data, stripHTMLTags(caption), "")
		}
		return err
	}
	return nil
}

func (t *Telegram) sendDocumentOnce(filename string, data []byte, caption, parseMode string) error {
	token, chatID := t.getCredentials()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	_ = mw.WriteField("chat_id", chatID)
	if caption != "" {
		_ = mw.WriteField("caption", caption)
	}
	if parseMode != "" {
		_ = mw.WriteField("parse_mode", parseMode)
	}

	part, err := mw.CreateFormFile("document", filename)
	if err != nil {
		return fmt.Errorf("multipart form: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	if err := mw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, t.endpoint(token, "sendDocument"), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := t.docClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram sendDocument failed: %s", redactToken(err.Error(), token))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		apiErr := fmt.Errorf("telegram sendDocument status %d: %s", resp.StatusCode, redactToken(strings.TrimSpace(string(body)), token))
		if resp.StatusCode == http.StatusBadRequest {
			return &badRequestError{err: apiErr}
		}
		return apiErr
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	log.Printf("[Telegram] Document sent: %s (%d bytes)", filename, len(data))
	return nil
}

func (t *Telegram) endpoint(token, method string) string {
	t.mu.RLock()
	base := t.apiBase
	t.mu.RUnlock()
	if base == "" {
		base = defaultAPIBase
	}
	return strings.TrimRight(base, "/") + "/bot" + token + "/" + method
}

// ---------------------------------------------------------------------------
// Message formatting (HTML, Bahasa Indonesia, emoji hanya di judul)
// ---------------------------------------------------------------------------

// esc membersihkan nilai dinamis (path, alasan, ID, hash) lalu meng-escape
// HTML, sehingga karakter < > & dari nama file tidak bisa merusak format
// pesan atau menyuntikkan tag.
func esc(s string) string {
	return html.EscapeString(cleanText(s))
}

// stripHTMLTags menghapus tag HTML dari pesan (untuk pengiriman ulang sebagai
// teks biasa). Hanya tag yang dipakai formatter sendiri yang dihapus; nilai
// dinamis sudah di-escape sehingga tidak ada tag lain di dalam pesan.
var htmlTagReplacer = strings.NewReplacer(
	"<b>", "", "</b>", "",
	"<i>", "", "</i>", "",
	"<code>", "", "</code>", "",
)

func stripHTMLTags(s string) string {
	return htmlTagReplacer.Replace(s)
}

func formatAlertMessage(block *models.Block) string {
	if block == nil {
		return "🛡️ <b>FIM-IPL · Perubahan File Terdeteksi</b>\n\nDetail anomali tidak tersedia."
	}

	var b strings.Builder
	if block.Action == models.ActionQuarantineBreach {
		b.WriteString("🚨 <b>URGENT · FIM-IPL · Karantina Dibatalkan</b>\n\n")
		fmt.Fprintf(&b, "<b>%s</b> · %s\n", esc(block.Action), esc(actionDesc(block.Action)))
	} else {
		b.WriteString("🛡️ <b>FIM-IPL · Perubahan File Terdeteksi</b>\n\n")
		fmt.Fprintf(&b, "<b>%s</b> · %s\n", esc(block.Action), esc(actionDesc(block.Action)))
	}
	fmt.Fprintf(&b, "<b>Blok:</b> <code>%s</code>\n", esc(block.ID))
	fmt.Fprintf(&b, "<b>Waktu:</b> %s\n", esc(formatTimestamp(block.Timestamp)))
	fmt.Fprintf(&b, "<b>File:</b> <code>%s</code>\n", esc(block.FilePath))
	fmt.Fprintf(&b, "<b>Status:</b> %s\n", esc(quarantineStatus(block)))
	fmt.Fprintf(&b, "<b>Hash sebelum:</b> <code>%s</code>\n", esc(truncateHash(block.OldHash)))
	fmt.Fprintf(&b, "<b>Hash sesudah:</b> <code>%s</code>\n", esc(truncateHash(block.NewHash)))
	if block.Action == models.ActionModeChanged || block.Action == models.ActionQuarantineBreach {
		fmt.Fprintf(&b, "<b>Izin sebelum:</b> <code>%04o</code>\n", block.OldMode)
		fmt.Fprintf(&b, "<b>Izin sesudah:</b> <code>%04o</code>\n", block.NewMode)
	}
	// Hash blok LENGKAP (T-06): jangkar eksternal. Bila rantai di server
	// dipotong ekornya, head hash di Telegram tidak akan cocok dengan
	// head hash rantai saat ini — itulah yang mendeteksi pemotongan yang
	// tidak bisa dideteksi verifikasi lokal.
	fmt.Fprintf(&b, "<b>Block hash:</b> <code>%s</code>\n", esc(block.BlockHash))

	b.WriteString("\n<b>Tindakan yang disarankan:</b>\n")
	switch {
	case block.Action == models.ActionQuarantineBreach:
		b.WriteString("1. URGENT: file yang sudah dikarantina diaktifkan lagi oleh pemiliknya; sistem sudah mengarantina ulang secara otomatis.\n")
		b.WriteString("2. Cari tahu siapa/apa yang mengubah izin file (akun www-data, proses web, atau penyerang yang menguasai akun itu).\n")
		b.WriteString("3. Jangan lepas karantina sebelum penyebabnya jelas; bila pemilik sah yang mengubah, perbaiki lewat maintenance mode + baseline/update.\n")
	case block.Action == models.ActionDeleted:
		b.WriteString("1. Pastikan penghapusan file memang dilakukan oleh admin atau proses resmi.\n")
		b.WriteString("2. Jika tidak dikenal, pulihkan file dari backup terakhir.\n")
		b.WriteString("3. Periksa akun admin dan log akses web server.\n")
	case block.Action == models.ActionUnreadable:
		b.WriteString("1. Periksa izin file/folder dan pastikan file bukan symlink.\n")
		b.WriteString("2. Bandingkan file dengan backup terakhir sebelum membukanya.\n")
		b.WriteString("3. Jika tidak dikenal, pindahkan file dari web root dan audit akun akses.\n")
	case block.QuarantineErr != "":
		b.WriteString("1. Nonaktifkan akses ke file melalui firewall, WAF, atau pindahkan file secara manual.\n")
		b.WriteString("2. Periksa isi file dan log akses web server.\n")
		b.WriteString("3. Perbaiki izin folder, lalu jalankan karantina ulang.\n")
	default:
		b.WriteString("1. Konfirmasi apakah perubahan dilakukan oleh admin atau proses update resmi.\n")
		b.WriteString("2. Jika tidak dikenal, periksa isi file dan log akses web server.\n")
		b.WriteString("3. Lepas karantina hanya setelah file dipastikan aman.\n")
	}
	return b.String()
}

func formatBatchMessage(blocks []*models.Block, total int) string {
	modified, created, deleted, unreadable := countActions(blocks)

	var b strings.Builder
	b.WriteString("🛡️ <b>FIM-IPL · Ringkasan Anomali</b>\n\n")
	fmt.Fprintf(&b, "<b>Waktu:</b> %s\n", esc(formatTimestamp(time.Now())))
	fmt.Fprintf(&b, "<b>Total file:</b> %d\n", total)
	fmt.Fprintf(&b, "<b>Rincian:</b> %d diubah, %d baru, %d dihapus, %d tidak dapat dipindai\n", modified, created, deleted, unreadable)

	b.WriteString("\n<b>File yang terdeteksi:</b>\n")
	listed := 0
	for _, block := range blocks {
		if block == nil || listed >= maxListedFiles {
			continue
		}
		listed++
		fmt.Fprintf(&b, "%d. <code>%s</code> · %s · <code>%s</code> · hash <code>%s</code>\n", listed, esc(block.FilePath), esc(block.Action), esc(block.ID), esc(truncateHash(block.BlockHash)))
	}
	if remaining := total - listed; remaining > 0 {
		fmt.Fprintf(&b, "... dan %d file lainnya.\n", remaining)
	}
	// Jangkar eksternal (T-06): blok terakhir + hash rantai penuh, agar
	// pemotongan ekor terdeteksi dari Telegram walau verifikasi lokal
	// terhadap rantai yang terpotong tetap lolos.
	if head := headBlock(blocks); head != nil {
		fmt.Fprintf(&b, "\n<b>Block terakhir:</b> <code>%s</code>\n<b>Hash rantai:</b> <code>%s</code>\n", esc(head.ID), esc(head.BlockHash))
	}

	b.WriteString("\nDetail lengkap tersedia di dashboard, menu Audit Trail.")
	return b.String()
}

func formatBulkWarningMessage(total int, blocks []*models.Block) string {
	modified, created, deleted, unreadable := countActions(blocks)

	var b strings.Builder
	b.WriteString("⚠️ <b>FIM-IPL · Perubahan Massal Terdeteksi</b>\n\n")
	fmt.Fprintf(&b, "<b>Waktu:</b> %s\n", esc(formatTimestamp(time.Now())))
	fmt.Fprintf(&b, "<b>Jumlah perubahan:</b> %d file\n", total)
	if len(blocks) > 0 {
		fmt.Fprintf(&b, "<b>Rincian:</b> %d modified, %d created, %d deleted, %d unreadable\n", modified, created, deleted, unreadable)
	}

	b.WriteString("\n<b>Kemungkinan penyebab:</b>\n")
	b.WriteString("• Update CMS, plugin, atau tema WordPress\n")
	b.WriteString("• Pemasangan atau penghapusan plugin\n")
	b.WriteString("• Operasi massal oleh administrator\n")

	// Jangkar eksternal (T-06): lihat formatBatchMessage.
	if head := headBlock(blocks); head != nil {
		fmt.Fprintf(&b, "\n<b>Block terakhir:</b> <code>%s</code>\n<b>Hash rantai:</b> <code>%s</code>\n", esc(head.ID), esc(head.BlockHash))
	}

	b.WriteString("\n<b>Tindakan:</b>\n")
	b.WriteString("1. Jika sedang melakukan update, aktifkan maintenance mode.\n")
	b.WriteString("2. Jika tidak ada aktivitas admin, periksa dashboard dan log akses server.\n")
	b.WriteString("3. Backup ledger otomatis dijalankan untuk anomali kritis.\n")
	return b.String()
}

// headBlock mengembalikan blok dengan ID terbesar (blok terakhir rantai)
// dari daftar, atau nil bila daftar kosong. Blok-blok yang masuk alert
// diurutkan menaik berdasarkan ID, tetapi pencarian eksplisit lebih aman
// daripada mengandalkan urutan.
func headBlock(blocks []*models.Block) *models.Block {
	var head *models.Block
	for _, block := range blocks {
		if block == nil {
			continue
		}
		if head == nil || block.ID > head.ID {
			head = block
		}
	}
	return head
}

func countActions(blocks []*models.Block) (modified, created, deleted, unreadable int) {
	for _, block := range blocks {
		if block == nil {
			continue
		}
		switch block.Action {
		case models.ActionModified:
			modified++
		case models.ActionCreated:
			created++
		case models.ActionDeleted:
			deleted++
		case models.ActionUnreadable:
			unreadable++
		}
	}
	return modified, created, deleted, unreadable
}

// actionDesc adalah label Bahasa Indonesia untuk satu aksi (tanpa kode aksi).
func actionDesc(action string) string {
	switch action {
	case models.ActionModified:
		return "isi file berubah"
	case models.ActionCreated:
		return "file baru"
	case models.ActionDeleted:
		return "file dihapus"
	case models.ActionModeChanged:
		return "izin file berubah"
	case models.ActionUnreadable:
		return "file tidak dapat dipindai"
	case models.ActionQuarantineBreach:
		return "karantina dibatalkan pemilik berkas"
	case models.ActionReleased:
		return "karantina dilepas"
	default:
		return cleanText(action)
	}
}

func quarantineStatus(block *models.Block) string {
	switch {
	case block.Action == models.ActionDeleted:
		return "Tidak berlaku (file sudah dihapus)"
	case block.Action == models.ActionUnreadable:
		state := "Tidak dikarantina"
		if block.Quarantined {
			state = "berhasil dinonaktifkan"
		}
		reason := "tidak dapat dibaca atau berupa symlink"
		if block.QuarantineErr != "" {
			reason = cleanText(block.QuarantineErr)
		}
		return "Tidak dapat dipindai: " + reason + "; karantina: " + state
	case block.Quarantined:
		return "Berhasil dikarantina (file dinonaktifkan)"
	case block.QuarantineErr != "":
		return "GAGAL dikarantina: " + cleanText(block.QuarantineErr)
	default:
		return "Tidak dikarantina"
	}
}

func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "(tidak tersedia)"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

func truncateHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return "(tidak ada)"
	}
	if len(hash) <= 16 {
		return hash
	}
	return hash[:8] + "..." + hash[len(hash)-8:]
}

// cleanText menghapus karakter kontrol agar nama file atau alasan dari sistem
// tidak dapat memalsukan struktur pesan Telegram.
func cleanText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(tidak tersedia)"
	}
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if r < 32 {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// redactToken mencegah token bot bocor ke log atau respons API melalui pesan
// error transport (Go menyertakan URL lengkap pada error jaringan).
func redactToken(text, token string) string {
	if token == "" {
		return text
	}
	return strings.ReplaceAll(text, token, "<token>")
}
