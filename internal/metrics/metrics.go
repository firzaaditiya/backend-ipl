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
	metric models.ScanMetric
}

// Start memulai pengukuran siklus scan. Aman dipanggil di goroutine terpisah.
func Start() *Cycle {
	return &Cycle{
		start: time.Now(),
	}
}

// MarkSkipped menandai cycle di-skip (mis. saat maintenance mode aktif).
func (c *Cycle) MarkSkipped(reason string) {
	c.metric.Skipped = true
	c.metric.SkipReason = reason
}

// Finish menutup pengukuran dan mengembalikan ScanMetric yang siap disimpan.
// filesScanned, anomalies, dan quarantined diisi oleh caller berdasarkan
// hasil scan cycle yang sesungguhnya. MemAllocBytes/MemSysBytes adalah heap
// runtime Go pada AKHIR siklus, bukan alokasi yang dipakai siklus itu
// (field memPre yang dulu mencatat awal siklus sudah dihapus di v1.5.0
// karena tidak pernah dibaca dan menyesatkan bila dikutip sebagai
// "memori per siklus").
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
