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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skripsi/fim-ipl/internal/ledger"
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
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
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

	return fmt.Sprintf(
		"FIM-IPL: BACKUP LEDGER\n\n"+
			"Jenis       : %s\n"+
			"Waktu       : %s\n"+
			"Total blok  : %d\n"+
			"Verifikasi  : %s\n"+
			"Head hash   : %s\n"+
			"File        : %s\n\n"+
			"Simpan head hash ini di luar server untuk mendeteksi penghapusan blok terakhir.",
		label, exp.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
		exp.TotalBlocks, verifyLabel(exp.Verify.Valid), headHash, filename,
	)
}

func (m *Manager) postWebhook(url, filename string, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FIM-IPL-File", filename)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Baca body agar koneksi dapat dipakai ulang (connection reuse).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
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
