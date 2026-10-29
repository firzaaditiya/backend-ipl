// Package metrics menyediakan kolektor untuk mencatat performa FIM Engine
// (response time & memory usage) per siklus pemindaian. Metrik disimpan ke
// dalam ledger (bucket "metrics") sehingga bisa ditarik ulang oleh dashboard
// untuk keperluan grafik dan laporan skripsi.
package metrics

import (
	"runtime"
	"time"

	"github.com/skripsi/fim-ipl/internal/models"
)

// Cycle merepresentasikan pengukuran satu siklus scan.
// Gunakan Start() untuk mulai, Finish() untuk menutup dan mendapatkan hasil.
type Cycle struct {
	start  time.Time
	memPre uint64
	metric models.ScanMetric
}

// Start memulai pengukuran siklus scan. Aman dipanggil di goroutine terpisah.
func Start() *Cycle {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &Cycle{
		start:  time.Now(),
		memPre: m.Alloc,
	}
}

// MarkSkipped menandai cycle di-skip (mis. saat maintenance mode aktif).
func (c *Cycle) MarkSkipped(reason string) {
	c.metric.Skipped = true
	c.metric.SkipReason = reason
}

// Finish menutup pengukuran dan mengembalikan ScanMetric yang siap disimpan.
// filesScanned, anomalies, dan quarantined diisi oleh caller berdasarkan
// hasil scan cycle yang sesungguhnya.
func (c *Cycle) Finish(filesScanned, anomalies, quarantined int) models.ScanMetric {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.metric.Timestamp = time.Now().UTC()
	c.metric.ElapsedMs = time.Since(c.start).Milliseconds()
	c.metric.MemAllocBytes = m.Alloc
	c.metric.MemSysBytes = m.Sys
	c.metric.FilesScanned = filesScanned
	c.metric.Anomalies = anomalies
	c.metric.Quarantined = quarantined

	return c.metric
}
