// Package backup mengekspor isi ledger secara periodik (setiap 24 jam) atau
// on-demand (mis. saat anomali kritis terdeteksi). Tujuan pengiriman
// mendukung dua channel:
//
//  1. Telegram — sebagai dokumen JSON via method sendDocument.
//  2. HTTP Webhook eksternal — POST JSON ke URL yang dikonfigurasi.
//
// Kedua channel opsional; jika salah satu tidak dikonfigurasi, jalur tersebut
// dilewati tanpa menghentikan proses backup.
package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/netguard"
	"github.com/skripsi/fim-ipl/internal/notifier"
)

// Manager mengelola scheduler backup dan menyediakan trigger manual.
type Manager struct {
	ledger     *ledger.Ledger
	telegram   *notifier.Telegram
	webhookURL string

	mu         sync.RWMutex
	interval   time.Duration
	stopCh     chan struct{}
	running    bool
	closed     bool
	lastRunAt  time.Time
	httpClient *http.Client

	// allowLocalWebhook HANYA untuk pengujian (di-set langsung oleh test
	// dalam paket ini): mengizinkan webhook ke 127.0.0.1 agar httptest bisa
	// dipakai. Tidak ada jalur konfigurasi/env yang mengaktifkannya, jadi
	// produksi selalu memvalidasi target webhook sebagai alamat publik.
	allowLocalWebhook bool

	// webhookSecret menandatangani export webhook (HMAC-SHA256). Diisi
	// dari environment (FIM_WEBHOOK_SECRET) lewat SetWebhookSecret;
	// TIDAK PERNAH ditulis ke config.json dan tidak bisa diubah lewat
	// Settings API. Kosong = webhook dikirim tanpa tanda tangan.
	webhookSecret string

	// runMu menyerialkan seluruh eksekusi backup. Tanpa ini, backup manual,
	// backup terjadwal, dan backup anomali kritis dapat berjalan bersamaan dan
	// mengirim dokumen ganda.
	runMu sync.Mutex
	wg    sync.WaitGroup
}

// NewManager membuat Manager baru.
// interval == 0 → default 24 jam.
func NewManager(l *ledger.Ledger, tg *notifier.Telegram, webhookURL string, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &Manager{
		ledger:     l,
		telegram:   tg,
		webhookURL: webhookURL,
		interval:   interval,
		httpClient: newWebhookClient(),
	}
}

// newWebhookClient membuat HTTP client khusus webhook: tidak mengikuti
// redirect apa pun (redirect 307/308 dapat meneruskan body export ledger ke
// host lain), dan DialContext-nya menolak alamat non-publik pada saat koneksi
// dibuat — validasi saat penyimpanan saja tidak cukup karena DNS dapat
// berubah (rebinding) setelah URL disimpan.
func newWebhookClient() *http.Client {
	transport := &http.Transport{
		DialContext: guardedDialContext,
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		// Tolak semua redirect: respons 3xx dikembalikan apa adanya dan
		// postWebhook mengubahnya menjadi error (lihat di bawah).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}
}

func guardedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// Resolve SEKALI, lalu dial alamat IP literal hasil validasi — bukan
	// hostname-nya lagi. Resolve kedua di dalam DialContext membuka jendela
	// DNS-rebinding: jawaban validasi (IP publik) dan jawaban dial (IP
	// internal) bisa berbeda bila penyerang mengendalikan DNS target.
	// Untuk HTTPS, SNI/verifikasi sertifikat tetap memakai hostname dari
	// URL (http.Transport yang mengatur TLS), jadi dial ke IP literal
	// tidak melemahkan TLS.
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		resolved, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		ips = resolved
	}
	for _, ip := range ips {
		if netguard.IsInternalIP(ip) {
			return nil, fmt.Errorf("webhook host %q resolves to non-public address", host)
		}
	}

	var d net.Dialer
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// SetWebhookSecret mengisi secret HMAC untuk menandatangani export webhook.
// Dipanggil sekali saat startup dari environment (FIM_WEBHOOK_SECRET);
// tidak ada jalur runtime yang mengubahnya.
func (m *Manager) SetWebhookSecret(secret string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webhookSecret = secret
}

// Start menjalankan scheduler backup di goroutine terpisah. Aman dipanggil
// berkali-kali; pemanggilan kedua akan diabaikan.
func (m *Manager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.closed = false
	m.stopCh = make(chan struct{})
	stopCh := m.stopCh
	interval := m.interval
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		log.Printf("[Backup] Scheduler started (interval=%s)", interval)

		for {
			select {
			case <-ticker.C:
				if err := m.RunOnce("scheduled"); err != nil {
					log.Printf("[Backup] Scheduled run failed: %v", err)
				}
			case <-stopCh:
				log.Println("[Backup] Scheduler stopped")
				return
			}
		}
	}()
}

// Stop menghentikan scheduler dan menunggu backup yang sedang berjalan selesai.
// Penting saat shutdown: ledger (Bbolt) tidak boleh ditutup saat export masih
// membaca database.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.running {
		close(m.stopCh)
		m.running = false
	}
	m.closed = true
	m.mu.Unlock()

	m.wg.Wait()

	// Tunggu RunOnce yang mungkin dipicu manual/goroutine anomali kritis.
	m.runMu.Lock()
	m.runMu.Unlock()
}

// UpdateWebhook memperbarui URL webhook secara thread-safe.
func (m *Manager) UpdateWebhook(url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webhookURL = url
}

// LastRunAt mengembalikan waktu run terakhir (bisa zero-value).
func (m *Manager) LastRunAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRunAt
}

// RunOnce mengeksekusi satu siklus backup. label dipakai sebagai identifier
// pada nama file & log (mis. "scheduled", "manual", "critical-anomaly").
func (m *Manager) RunOnce(label string) error {
	m.runMu.Lock()
	defer m.runMu.Unlock()

	m.mu.RLock()
	closed := m.closed
	webhook := m.webhookURL
	m.mu.RUnlock()
	if closed {
		return fmt.Errorf("backup manager already stopped")
	}

	telegramConfigured := m.telegram != nil && m.telegram.IsConfigured()
	if !telegramConfigured && webhook == "" {
		return fmt.Errorf("no backup channel configured")
	}

	exp, err := m.ledger.ExportAll(true)
	if err != nil {
		return fmt.Errorf("export ledger: %w", err)
	}

	data, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export: %w", err)
	}

	label = sanitizeLabel(label)
	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("fim-ipl-ledger-%s-%s.json", label, ts)
	caption := formatCaption(label, filename, exp)

	var telegramErr, webhookErr error

	// 1) Telegram document
	if telegramConfigured {
		if err := m.telegram.SendDocument(filename, data, caption); err != nil {
			telegramErr = err
			log.Printf("[Backup] Telegram send failed: %v", err)
		}
	}

	// 2) HTTP Webhook
	if webhook != "" {
		if err := m.postWebhook(webhook, filename, data); err != nil {
			webhookErr = err
			log.Printf("[Backup] Webhook post failed: %v", err)
		}
	}

	m.mu.Lock()
	m.lastRunAt = time.Now()
	m.mu.Unlock()

	if telegramErr != nil && webhookErr != nil {
		return fmt.Errorf("both channels failed: telegram=%v webhook=%v", telegramErr, webhookErr)
	}

	log.Printf("[Backup] Run OK (label=%s, blocks=%d, size=%d bytes)", label, exp.TotalBlocks, len(data))
	return nil
}

func formatCaption(label, filename string, exp *ledger.LedgerExport) string {
	headHash := strings.TrimSpace(exp.HeadHash)
	if headHash == "" {
		headHash = "(belum ada blok)"
	}
	headBlockID := strings.TrimSpace(exp.HeadBlockID)
	if headBlockID == "" {
		headBlockID = "(belum ada blok)"
	}

	return fmt.Sprintf(
		"💾 <b>FIM-IPL · Backup Ledger</b>\n\n"+
			"<b>Jenis:</b> %s\n"+
			"<b>Waktu:</b> %s\n"+
			"<b>Total blok:</b> %d\n"+
			"<b>Verifikasi:</b> %s %s\n"+
			"<b>Block terakhir:</b> <code>%s</code>\n"+
			"<b>Head hash:</b> <code>%s</code>\n"+
			"<b>File:</b> <code>%s</code>\n\n"+
			"Simpan head hash ini di luar server untuk mendeteksi penghapusan blok terakhir.",
		html.EscapeString(label), exp.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
		exp.TotalBlocks, verifyIcon(exp.Verify.Valid), verifyLabel(exp.Verify.Valid), html.EscapeString(headBlockID), html.EscapeString(headHash), html.EscapeString(filename),
	)
}

// verifyIcon menandai hasil verifikasi rantai pada caption backup.
func verifyIcon(valid bool) string {
	if valid {
		return "✅"
	}
	return "❌"
}

func (m *Manager) postWebhook(url, filename string, payload []byte) error {
	// Validasi ulang sesaat sebelum pengiriman: URL yang lolos saat
	// disimpan dapat berubah menjadi internal bila DNS-nya di-rebind.
	// (allowLocalWebhook hanya di-set oleh pengujian dalam paket ini.)
	if !m.allowLocalWebhook {
		if err := netguard.ValidatePublicURL(url); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FIM-IPL-File", filename)
	// Tanda tangani export agar penerima bisa membedakan export asli dari
	// POST palsu: HMAC-SHA256(secret, timestamp + "." + body). Penerima
	// menghitung ulang HMAC yang sama, membandingkan constant-time, dan
	// menolak timestamp lebih tua dari 5 menit (anti-replay). Tanpa secret
	// yang dikonfigurasi, header tidak dikirim (perilaku lama).
	m.mu.RLock()
	secret := m.webhookSecret
	m.mu.RUnlock()
	if secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "."))
		mac.Write(payload)
		req.Header.Set("X-FIM-IPL-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		req.Header.Set("X-FIM-IPL-Timestamp", ts)
	}

	resp, err := m.webhookClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Redirect tidak diikuti (lihat newWebhookClient): respons 3xx di sini
	// berarti target mencoba mengalihkan export ledger ke host lain.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("webhook redirect not allowed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Baca body agar koneksi dapat dipakai ulang (connection reuse).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// webhookClient mengembalikan client yang dipakai postWebhook. Bila
// allowLocalWebhook aktif (hanya pengujian dalam paket ini, httptest di
// 127.0.0.1), dipakai client tanpa dial guard — kalau tidak, guard akan
// menolak koneksi test itu sendiri. Produksi selalu memakai m.httpClient
// (dial guard + tolak redirect).
func (m *Manager) webhookClient() *http.Client {
	if m.allowLocalWebhook {
		return &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return m.httpClient
}

func verifyLabel(valid bool) string {
	if valid {
		return "UTUH"
	}
	return "TIDAK UTUH"
}

// sanitizeLabel membatasi label pada karakter aman agar tidak bisa dipakai
// untuk path traversal pada nama file export.
func sanitizeLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return "manual"
	}
	label = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, label)
	return strings.Trim(label, "-")
}
