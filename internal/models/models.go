package models

import "time"

// Action adalah nilai valid untuk Block.Action.
const (
	ActionCreated  = "CREATED"
	ActionModified = "MODIFIED"
	ActionDeleted  = "DELETED"
	// ActionModeChanged mencatat perubahan izin (mode) berkas yang isinya
	// TIDAK berubah. Sejak v1.5.0, pemindaian membandingkan hash DAN mode:
	// chmod 777 pada wp-config.php sebelumnya lolos tanpa jejak karena
	// hash-nya sama; kini tercatat sebagai MODE_CHANGED lalu dikarantina
	// seperti MODIFIED. Aksi ini adalah field yang sudah di-hash, jadi
	// penambahannya tidak mengubah formula hash blok.
	ActionModeChanged = "MODE_CHANGED"
	// ActionUnreadable mencatat file yang ada di disk tetapi tidak dapat
	// dibaca/di-hash (izin ditolak, symlink, atau error I/O). Tanpa aksi ini,
	// file yang sengaja dibuat tidak terbaca akan tampak seperti DELETED dan
	// baseline bisa terhapus sehingga blind spot tidak pernah dilaporkan.
	ActionUnreadable = "UNREADABLE"
	// ActionReleased mencatat pelepasan karantina oleh Super Admin. Bukan
	// temuan pemindaian, tetapi tetap masuk ledger agar tindakan manual
	// tercatat dan tidak bisa dihapus tanpa merusak hash-chain.
	ActionReleased = "RELEASED"
	// Aksi administratif (sejak v1.6.0, T-03): tindakan operator yang
	// dicatat di ledger agar jejak "siapa, kapan, apa" bersifat append-only
	// dan ikut terlindungi hash-chain v2. Bukan anomali pemindaian — tidak
	// dihitung sebagai anomali di GetDashboardCounts dan tidak memicu
	// alert Telegram.
	ActionBaselineInit    = "BASELINE_INIT"
	ActionBaselineUpdate  = "BASELINE_UPDATE"
	ActionMonitoringStart = "MONITORING_START"
	ActionMonitoringStop  = "MONITORING_STOP"
	ActionMaintenanceOn   = "MAINTENANCE_ON"
	ActionMaintenanceOff  = "MAINTENANCE_OFF"
	ActionSettingsChanged = "SETTINGS_CHANGED"
	ActionAuditorSet      = "AUDITOR_SET"
	// ActionQuarantineBreach mencatat pembatalan karantina oleh pemilik
	// berkas (sejak v1.6.0, T-01): berkas yang tercatat dikarantina
	// ternyata izinnya sudah dipulihkan (mis. chmod 644 oleh www-data)
	// sehingga dapat dibaca/dijalankan lagi, padahal hash dan izinnya sama
	// dengan baseline dan perbandingan biasa tidak memicu event apa pun.
	// OldMode pada aksi ini selalu 000 (izin yang seharusnya berlaku saat
	// dikarantina); NewMode adalah izin yang ditemukan saat pemeriksaan.
	ActionQuarantineBreach = "QUARANTINE_BREACH"
)

// AdminBlockPath adalah FilePath yang dipakai blok aksi administratif:
// tidak ada berkas yang terlibat, jadi dipakai penanda yang bisa dicari
// di Audit Trail.
const AdminBlockPath = "[admin]"

// IsAnomalyAction membedakan temuan pemindaian (dihitung sebagai anomali
// dan memicu alert) dari tindakan manual/administratif (RELEASED dan
// aksi administratif T-03) yang hanya dicatat di ledger.
func IsAnomalyAction(action string) bool {
	switch action {
	case ActionCreated, ActionModified, ActionModeChanged, ActionQuarantineBreach, ActionDeleted, ActionUnreadable:
		return true
	default:
		return false
	}
}

// Block adalah unit data pada Private Ledger. Bersifat append-only dan
// terhubung ke blok sebelumnya melalui PrevBlockHash sehingga membentuk
// hash-chain lokal untuk bukti perubahan.
type Block struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	FilePath  string    `json:"file_path"`
	Action    string    `json:"action"`
	OldHash   string    `json:"old_hash"`
	NewHash   string    `json:"new_hash"`
	// OldMode/NewMode adalah izin berkas (perm bits, mis. 0644) sebelum dan
	// sesudah kejadian. Dipakai aksi MODE_CHANGED dan QUARANTINE_BREACH;
	// untuk aksi lain diisi bila diketahui. Pada blok v1 keduanya TIDAK
	// ikut dihitung ke dalam block hash (metadata tampilan saja); pada
	// blok v2 keduanya ikut dihitung (lihat calculateBlockHashV2).
	OldMode       uint32 `json:"old_mode,omitempty"`
	NewMode       uint32 `json:"new_mode,omitempty"`
	Quarantined   bool   `json:"quarantined"`
	QuarantineErr string `json:"quarantine_err,omitempty"`
	// Actor adalah pelaku aksi administratif (nama pengguna, peran, dan IP
	// klien — diisi sejak T-03; kosong untuk temuan pemindaian). Ikut
	// dihitung ke dalam hash blok v2, agar jejak "siapa" tidak bisa
	// diubah tanpa merusak rantai.
	Actor string `json:"actor,omitempty"`
	// Detail adalah keterangan bebas tentang aksi (mis. alasan pelepasan
	// karantina — diisi sejak T-03). Ikut dihitung ke dalam hash blok v2.
	Detail string `json:"detail,omitempty"`
	// BaselineDigest adalah SHA-256 atas seluruh isi baseline pada saat
	// blok ini ditulis (hanya pada BASELINE_INIT/BASELINE_UPDATE, sejak
	// v1.6.0, T-04). Ikut dihitung ke dalam hash blok v3, sehingga
	// perubahan diam-diam pada baseline dapat dideteksi dengan
	// membandingkan digest ini dengan digest baseline saat ini.
	BaselineDigest string `json:"baseline_digest,omitempty"`
	// BaselineCount adalah jumlah berkas dalam baseline pada saat blok
	// ini ditulis. Ikut dihitung ke dalam hash blok v3.
	BaselineCount int    `json:"baseline_count,omitempty"`
	PrevBlockHash string `json:"prev_block_hash"`
	BlockHash     string `json:"block_hash"`
	// HashVersion adalah versi formula block hash. 0 (field tidak ada) =
	// v1: formula lama dengan pemisah "|" yang hanya melindungi
	// ID|Timestamp|FilePath|Action|OldHash|NewHash|PrevBlockHash|
	// Quarantined. 2 = v2 (sejak v1.6.0): encoding length-prefixed yang
	// melindungi seluruh field kejadian. 3 = v3 (sejak v1.6.0, T-04): v2
	// ditambah BaselineDigest dan BaselineCount. Tidak ada versi 1 — v1
	// adalah ketiadaan field ini, agar blok produksi lama tetap
	// terverifikasi tanpa perubahan apa pun.
	HashVersion int `json:"hash_version,omitempty"`
}

// FileRecord adalah snapshot integritas file yang disimpan di bucket baseline.
type FileRecord struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
	// Mode adalah perm bits (mis. 0644) saat baseline dicatat. Nilai 0
	// berarti "mode belum tercatat" (baseline dari sebelum v1.5.0): siklus
	// pertama setelah upgrade mengadopsi mode yang teramati tanpa
	// menimbulkan event (lihat CompareWithBaseline).
	Mode      uint32    `json:"mode,omitempty"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	ScannedAt time.Time `json:"scanned_at"`
}

// ScanResult adalah hasil hashing satu file oleh worker.
type ScanResult struct {
	Path string
	Hash string
	// Mode diisi dari Lstat, juga bila hashing gagal (mis. file tidak
	// terbaca): izin berkas tetap dapat diamati walau isinya tidak.
	Mode    uint32
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
	OldMode       uint32
	NewMode       uint32
	Quarantined   bool
	QuarantineErr string
	// ScanErr menyimpan alasan file tidak dapat di-hash (khusus UNREADABLE).
	// Tidak ikut dihitung ke dalam block hash karena Block tidak memilikinya;
	// alasan tetap disalin ke QuarantineErr saat block dibuat.
	ScanErr string
	// Actor/Detail dibawa ke Block untuk aksi administratif (T-03): siapa
	// yang melakukan dan mengapa. Kosong untuk temuan pemindaian.
	Actor  string
	Detail string
	// BaselineDigest/BaselineCount dibawa ke Block untuk aksi baseline
	// (T-04): digest dan jumlah berkas baseline yang baru dibuat.
	BaselineDigest string
	BaselineCount  int
}

// ScanMetric adalah data telemetri satu siklus scan.
// Digunakan untuk grafik performa di dashboard dan laporan skripsi.
type ScanMetric struct {
	Timestamp time.Time `json:"timestamp"`
	ElapsedMs int64     `json:"elapsed_ms"`
	// MemAllocBytes adalah heap Alloc runtime Go pada AKHIR siklus, bukan
	// alokasi yang dipakai oleh siklus itu (lihat metrics.Finish). Naskah
	// harus menyebutnya "alokasi heap pada akhir siklus".
	MemAllocBytes uint64 `json:"mem_alloc_bytes"`
	MemSysBytes   uint64 `json:"mem_sys_bytes"`
	FilesScanned  int    `json:"files_scanned"`
	Anomalies     int    `json:"anomalies"`
	Quarantined   int    `json:"quarantined"`
	// SkippedOversize menghitung file non-kode >50 MB yang dilewati pada
	// siklus ini (isinya tidak diperiksa; lihat ErrFileOversize).
	SkippedOversize int `json:"skipped_oversize,omitempty"`
	// ExcludedFiles menghitung berkas yang dikecualikan dari deteksi pada
	// siklus ini (exclude_globs atau kebijakan uploads, T-05). Angka ini
	// harus terlihat di dasbor agar pengecualian tidak menjadi blind
	// spot diam-diam.
	ExcludedFiles int    `json:"excluded_files,omitempty"`
	Skipped       bool   `json:"skipped,omitempty"`
	SkipReason    string `json:"skip_reason,omitempty"`
}

// LastVerification adalah hasil verifikasi terjadwal terakhir (T-06,
// v1.6.0): rantai + digest baseline. Disimpan di bucket meta agar
// bertahan melewati restart dan bisa ditampilkan dasbor ("terakhir
// diverifikasi") serta dibandingkan dengan jangkar eksternal (Telegram).
type LastVerification struct {
	VerifiedAt      time.Time `json:"verified_at"`
	ChainValid      bool      `json:"chain_valid"`
	ChainMessage    string    `json:"chain_message"`
	HeadBlockID     string    `json:"head_block_id,omitempty"`
	HeadHash        string    `json:"head_hash"`
	TotalBlocks     int       `json:"total_blocks"`
	BaselineMatch   bool      `json:"baseline_match"`
	BaselineBlockID string    `json:"baseline_block_id,omitempty"`
	BaselineMessage string    `json:"baseline_message"`
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
