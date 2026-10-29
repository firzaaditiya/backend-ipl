package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
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
// Pesan sengaja dikirim sebagai teks biasa (tanpa parse_mode) agar path file
// Windows/Linux, karakter khusus, dan nama file tidak merusak format atau
// ditolak Telegram.
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
		"FIM-IPL: TES NOTIFIKASI\n\n"+
			"Konfigurasi Telegram berhasil.\n\n"+
			"Waktu server : %s\n"+
			"Chat ID      : %s\n\n"+
			"Pesan ini berasal dari tombol uji di halaman Pengaturan. "+
			"Tidak ada perubahan file yang terkait dengan pesan ini.",
		formatTimestamp(time.Now()), cleanText(chatID),
	)
	return t.sendMessage(msg)
}

// SendSystemAlert mengirim kegagalan operasional (mis. watch path hilang atau
// tidak dapat diakses) yang membuat pemindaian tidak berjalan. Tanpa ini,
// kegagalan hanya terlihat di log server dan admin tidak mendapat peringatan.
func (t *Telegram) SendSystemAlert(title, detail string) error {
	if !t.IsConfigured() {
		return fmt.Errorf("telegram token or chat_id not configured")
	}

	msg := fmt.Sprintf(
		"FIM-IPL: %s\n\n"+
			"Waktu   : %s\n"+
			"Masalah : %s\n\n"+
			"Tindakan:\n"+
			"1. Pastikan watch path ada dan dapat dibaca oleh akun service FIM.\n"+
			"2. Periksa izin folder serta ruang disk.\n"+
			"3. Setelah diperbaiki, jalankan baseline ulang bila struktur file berubah.",
		cleanText(title), formatTimestamp(time.Now()), cleanText(detail),
	)
	return t.sendMessage(msg)
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

func (t *Telegram) sendMessage(text string) error {
	var lastErr error
	for attempt := 1; attempt <= sendMaxAttempts; attempt++ {
		err := t.sendMessageOnce(text)
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

func (t *Telegram) sendMessageOnce(text string) error {
	token, chatID := t.getCredentials()

	params := url.Values{}
	params.Set("chat_id", chatID)
	params.Set("text", text)
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
		b.WriteString("FIM-IPL: KARANTINA GAGAL - TINDAKAN DIPERLUKAN\n\n")
		fmt.Fprintf(&b, "Waktu  : %s\n", formatTimestamp(time.Now()))
		fmt.Fprintf(&b, "File   : %s\n", cleanText(failures[0].FilePath))
		fmt.Fprintf(&b, "Alasan : %s\n", cleanText(failures[0].Reason))
	} else {
		fmt.Fprintf(&b, "FIM-IPL: KARANTINA GAGAL PADA %d FILE\n\n", len(failures))
		fmt.Fprintf(&b, "Waktu : %s\n\n", formatTimestamp(time.Now()))
		b.WriteString("File yang gagal dinonaktifkan:\n")
		listed := 0
		for _, failure := range failures {
			if listed >= maxListedFiles {
				break
			}
			listed++
			fmt.Fprintf(&b, "%d. %s\n", listed, cleanText(failure.FilePath))
			fmt.Fprintf(&b, "   Alasan: %s\n", cleanText(failure.Reason))
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
	b.WriteString("Tindakan segera:\n")
	b.WriteString("1. Nonaktifkan akses ke file melalui firewall, WAF, atau pindahkan file secara manual.\n")
	b.WriteString("2. Periksa isi file dan log akses web server.\n")
	b.WriteString("3. Perbaiki izin folder, lalu jalankan karantina ulang.")
	return t.sendMessage(b.String())
}

// SendDocument mengirim file (byte slice) sebagai dokumen ke chat Telegram.
// Digunakan oleh modul backup untuk mengirim export JSON ledger.
func (t *Telegram) SendDocument(filename string, data []byte, caption string) error {
	if !t.IsConfigured() {
		return fmt.Errorf("telegram not configured")
	}
	token, chatID := t.getCredentials()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	_ = mw.WriteField("chat_id", chatID)
	if caption != "" {
		_ = mw.WriteField("caption", caption)
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
		return fmt.Errorf("telegram sendDocument status %d: %s", resp.StatusCode, redactToken(strings.TrimSpace(string(body)), token))
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
// Message formatting (plain text, Bahasa Indonesia, tanpa emoji)
// ---------------------------------------------------------------------------

func formatAlertMessage(block *models.Block) string {
	if block == nil {
		return "FIM-IPL: PERUBAHAN FILE TERDETEKSI\n\nDetail anomali tidak tersedia."
	}

	var b strings.Builder
	b.WriteString("FIM-IPL: PERUBAHAN FILE TERDETEKSI\n\n")
	fmt.Fprintf(&b, "Block        : %s\n", cleanText(block.ID))
	fmt.Fprintf(&b, "Waktu        : %s\n", formatTimestamp(block.Timestamp))
	fmt.Fprintf(&b, "Aksi         : %s\n", actionLabel(block.Action))
	fmt.Fprintf(&b, "File         : %s\n", cleanText(block.FilePath))
	fmt.Fprintf(&b, "Status file  : %s\n", quarantineStatus(block))
	fmt.Fprintf(&b, "Hash sebelum : %s\n", truncateHash(block.OldHash))
	fmt.Fprintf(&b, "Hash sesudah : %s\n", truncateHash(block.NewHash))

	b.WriteString("\nTindakan yang disarankan:\n")
	switch {
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
	b.WriteString("FIM-IPL: RINGKASAN ANOMALI\n\n")
	fmt.Fprintf(&b, "Waktu      : %s\n", formatTimestamp(time.Now()))
	fmt.Fprintf(&b, "Total file : %d\n", total)
	fmt.Fprintf(&b, "Modified   : %d\n", modified)
	fmt.Fprintf(&b, "Created    : %d\n", created)
	fmt.Fprintf(&b, "Deleted    : %d\n", deleted)
	fmt.Fprintf(&b, "Unreadable : %d\n", unreadable)

	b.WriteString("\nFile yang terdeteksi:\n")
	listed := 0
	for _, block := range blocks {
		if block == nil || listed >= maxListedFiles {
			continue
		}
		listed++
		fmt.Fprintf(&b, "%d. %s - %s\n", listed, actionLabel(block.Action), cleanText(block.FilePath))
	}
	if remaining := total - listed; remaining > 0 {
		fmt.Fprintf(&b, "... dan %d file lainnya.\n", remaining)
	}

	b.WriteString("\nDetail lengkap tersedia di dashboard, menu Audit Trail.")
	return b.String()
}

func formatBulkWarningMessage(total int, blocks []*models.Block) string {
	modified, created, deleted, unreadable := countActions(blocks)

	var b strings.Builder
	b.WriteString("FIM-IPL: PERUBAHAN MASSAL TERDETEKSI\n\n")
	fmt.Fprintf(&b, "Waktu            : %s\n", formatTimestamp(time.Now()))
	fmt.Fprintf(&b, "Jumlah perubahan : %d file\n", total)
	if len(blocks) > 0 {
		fmt.Fprintf(&b, "Rincian          : %d modified, %d created, %d deleted, %d unreadable\n", modified, created, deleted, unreadable)
	}

	b.WriteString("\nKemungkinan penyebab:\n")
	b.WriteString("- Update CMS, plugin, atau tema WordPress\n")
	b.WriteString("- Pemasangan atau penghapusan plugin\n")
	b.WriteString("- Operasi massal oleh administrator\n")

	b.WriteString("\nTindakan:\n")
	b.WriteString("1. Jika sedang melakukan update, aktifkan maintenance mode.\n")
	b.WriteString("2. Jika tidak ada aktivitas admin, periksa dashboard dan log akses server.\n")
	b.WriteString("3. Backup ledger otomatis dijalankan untuk anomali kritis.\n")
	return b.String()
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

func actionLabel(action string) string {
	switch action {
	case models.ActionModified:
		return "MODIFIED (isi file berubah)"
	case models.ActionCreated:
		return "CREATED (file baru)"
	case models.ActionDeleted:
		return "DELETED (file dihapus)"
	case models.ActionUnreadable:
		return "UNREADABLE (file tidak dapat dipindai)"
	case models.ActionReleased:
		return "RELEASED (karantina dilepas)"
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
