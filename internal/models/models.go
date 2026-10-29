package models

import "time"

// Action adalah nilai valid untuk Block.Action.
const (
	ActionCreated  = "CREATED"
	ActionModified = "MODIFIED"
	ActionDeleted  = "DELETED"
	// ActionUnreadable mencatat file yang ada di disk tetapi tidak dapat
	// dibaca/di-hash (izin ditolak, symlink, atau error I/O). Tanpa aksi ini,
	// file yang sengaja dibuat tidak terbaca akan tampak seperti DELETED dan
	// baseline bisa terhapus sehingga blind spot tidak pernah dilaporkan.
	ActionUnreadable = "UNREADABLE"
	// ActionReleased mencatat pelepasan karantina oleh Super Admin. Bukan
	// temuan pemindaian, tetapi tetap masuk ledger agar tindakan manual
	// tercatat dan tidak bisa dihapus tanpa merusak hash-chain.
	ActionReleased = "RELEASED"
)

// Block adalah unit data pada Private Ledger. Bersifat append-only dan
// terhubung ke blok sebelumnya melalui PrevBlockHash sehingga membentuk
// hash-chain lokal untuk bukti perubahan.
type Block struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	FilePath      string    `json:"file_path"`
	Action        string    `json:"action"`
	OldHash       string    `json:"old_hash"`
	NewHash       string    `json:"new_hash"`
	Quarantined   bool      `json:"quarantined"`
	QuarantineErr string    `json:"quarantine_err,omitempty"`
	PrevBlockHash string    `json:"prev_block_hash"`
	BlockHash     string    `json:"block_hash"`
}

// FileRecord adalah snapshot integritas file yang disimpan di bucket baseline.
type FileRecord struct {
	Path      string    `json:"path"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	ScannedAt time.Time `json:"scanned_at"`
}

// ScanResult adalah hasil hashing satu file oleh worker.
type ScanResult struct {
	Path    string
	Hash    string
	Size    int64
	ModTime time.Time
	Err     error
}

// AnomalyEvent adalah hasil diff antara scan dengan baseline.
// Diteruskan ke ledger untuk dijadikan Block.
type AnomalyEvent struct {
	FilePath      string
	Action        string
	OldHash       string
	NewHash       string
	Quarantined   bool
	QuarantineErr string
	// ScanErr menyimpan alasan file tidak dapat di-hash (khusus UNREADABLE).
	// Tidak ikut dihitung ke dalam block hash karena Block tidak memilikinya;
	// alasan tetap disalin ke QuarantineErr saat block dibuat.
	ScanErr string
}

// ScanMetric adalah data telemetri satu siklus scan.
// Digunakan untuk grafik performa di dashboard dan laporan skripsi.
type ScanMetric struct {
	Timestamp     time.Time `json:"timestamp"`
	ElapsedMs     int64     `json:"elapsed_ms"`
	MemAllocBytes uint64    `json:"mem_alloc_bytes"`
	MemSysBytes   uint64    `json:"mem_sys_bytes"`
	FilesScanned  int       `json:"files_scanned"`
	Anomalies     int       `json:"anomalies"`
	Quarantined   int       `json:"quarantined"`
	Skipped       bool      `json:"skipped,omitempty"`
	SkipReason    string    `json:"skip_reason,omitempty"`
}

type AppConfig struct {
	WatchPaths      []string `json:"watch_paths"`
	TelegramToken   string   `json:"telegram_token"`
	TelegramChatID  string   `json:"telegram_chat_id"`
	ScanIntervalSec int      `json:"scan_interval_sec"`
	WorkerCount     int      `json:"worker_count"`
	IsMonitoring    bool     `json:"is_monitoring"`
}

type DashboardStats struct {
	TotalFiles      int  `json:"total_files"`
	SafeFiles       int  `json:"safe_files"`
	TotalAnomalies  int  `json:"total_anomalies"`
	IsMonitoring    bool `json:"is_monitoring"`
	MaintenanceMode bool `json:"maintenance_mode"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Catatan v1.2.0: struct LoginResponse yang lama (dengan field Token) sengaja
// dihapus karena sejak v1.1.0 token tidak pernah dikembalikan di badan JSON;
// token hanya hidup di kuki HttpOnly. Menyimpan struct itu hanya akan
// membingungkan pembaca kode dan penguji yang mengira masih ada jalur token
// lewat JSON.
