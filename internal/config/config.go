package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	mu           sync.RWMutex    `json:"-"`
	filePath     string          `json:"-"`
	envOverrides map[string]bool `json:"-"`

	ServerPort string `json:"server_port"`
	JWTSecret  string `json:"jwt_secret"`
	LoginPath  string `json:"login_path"`

	// CookieSecure mengaktifkan atribut Secure pada cookie sesi. Default
	// true (aman): cookie hanya dikirim lewat HTTPS. Nonaktifkan hanya
	// untuk dev HTTP lokal lewat FIM_COOKIE_SECURE=0.
	CookieSecure bool `json:"cookie_secure"`

	// MonitoringEnabled adalah status monitoring yang DIPERTAHANKAN di
	// config.json (bukan rahasia deployment). True berarti monitoring
	// sedang berjalan saat terakhir diubah lewat API, sehingga daemon
	// melanjutkannya otomatis setelah restart. Berbeda dengan shutdown
	// proses (systemctl restart) yang TIDAK mengubah flag ini: restart
	// tidak dianggap sebagai perintah stop oleh admin.
	MonitoringEnabled bool `json:"monitoring_enabled"`

	// SessionEpoch adalah versi sesi: setiap perubahan kredensial
	// (SetupPassword / SetupAuditor) menaikkannya satu tingkat, sehingga
	// seluruh token JWT yang diterbitkan sebelumnya ditolak. Logout juga
	// mencabut token itu saja lewat denylist jti (sejak v1.5.0, lihat
	// ledger.RevokeToken); token yang sudah logout tidak lagi valid walau
	// belum kedaluwarsa 24 jam.
	SessionEpoch int `json:"session_epoch"`

	// WebhookSecret adalah secret HMAC untuk menandatangani export ledger
	// ke webhook (header X-FIM-IPL-Signature). Hanya dari environment
	// (FIM_WEBHOOK_SECRET); TIDAK PERNAH ditulis ke config.json (json:"-"
	// di struct ini dan di Snapshot) dan tidak bisa diubah lewat Settings
	// API. Kosong = webhook dikirim tanpa tanda tangan (penerima tidak
	// bisa membedakan export asli dari POST palsu).
	WebhookSecret string `json:"-"`

	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`

	// Auditor adalah role read-only (manajemen/kepala yayasan).
	// Kosong = belum dibuat; dibuat oleh Super Admin via POST /api/v1/setup/auditor.
	AuditorUsername string `json:"auditor_username"`
	AuditorPassword string `json:"auditor_password"`

	WatchPaths      []string `json:"watch_paths"`
	ScanIntervalSec int      `json:"scan_interval_sec"`
	WorkerCount     int      `json:"worker_count"`

	// ExcludeGlobs adalah pola path yang dikecualikan dari deteksi (T-05,
	// v1.6.0), relatif terhadap watch root ("wp-content/cache/**") atau
	// absolut. Default: direktori cache dan staging update WordPress.
	// Daftar kosong eksplisit berarti tidak ada pengecualian glob (tetapi
	// kebijakan uploads bawaan tetap berlaku — lihat scanner/exclude.go).
	ExcludeGlobs []string `json:"exclude_globs"`

	TelegramToken  string `json:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id"`

	BackupWebhookURL string `json:"backup_webhook_url"`

	// AllowedOrigins membatasi CORS sekaligus menjadi daftar origin yang
	// diizinkan pada pemeriksaan CSRF untuk request mutasi. Kosong berarti
	// TIDAK ada origin lintas situs yang diizinkan: header CORS tidak
	// dikirim, dan mutasi dengan Origin yang berbeda dari Host request
	// ditolak. Produksi wajib mengisinya dengan origin dashboard, mis.
	// https://fim.tpqalfawwaz.web.id.
	AllowedOrigins []string `json:"allowed_origins"`

	DBPath string `json:"db_path"`
}

var (
	instance *Config
	once     sync.Once
)

// DefaultExcludeGlobs adalah pola pengecualian bawaan T-05: direktori
// cache plugin dan staging update WordPress. Dipakai DefaultConfig dan
// sebagai fallback bila config.json berisi "exclude_globs": null.
var DefaultExcludeGlobs = []string{"wp-content/cache/**", "wp-content/upgrade/**"}

func DefaultConfig() *Config {
	return &Config{
		ServerPort:        ":8080",
		JWTSecret:         "",
		LoginPath:         "/api/v1/secure-gate",
		CookieSecure:      true,
		MonitoringEnabled: false,
		AdminUsername:     "",
		AdminPassword:     "",
		WatchPaths:        []string{},
		ScanIntervalSec:   300,
		WorkerCount:       4,
		// Default pengecualian T-05: cache plugin dan staging update
		// WordPress — direktori yang isinya berubah sendiri setiap saat
		// dan tidak pernah berisi kode yang dieksekusi langsung.
		ExcludeGlobs:   append([]string(nil), DefaultExcludeGlobs...),
		TelegramToken:  "",
		TelegramChatID: "",
		DBPath:         "./data/fim.db",
	}
}

func Load(path string) (*Config, error) {
	var err error
	once.Do(func() {
		instance = DefaultConfig()
		instance.filePath = path

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			err = initFreshConfig(instance, path)
			return
		}

		if jsonErr := json.Unmarshal(data, instance); jsonErr != nil {
			err = jsonErr
			return
		}
		if modeErr := hardenFileMode(path); modeErr != nil {
			err = modeErr
			return
		}

		changed := false

		// Migrasi transparan: config lama menyimpan password plaintext.
		// Setelah startup, seluruh password disimpan sebagai bcrypt.
		if hashed, ok := hashIfPlaintext(instance.AdminPassword); ok {
			instance.AdminPassword = hashed
			changed = true
		}
		if hashed, ok := hashIfPlaintext(instance.AuditorPassword); ok {
			instance.AuditorPassword = hashed
			changed = true
		}
		if instance.JWTSecret == "" {
			secret, secretErr := generateRandomSecret()
			if secretErr != nil {
				err = secretErr
				return
			}
			instance.JWTSecret = secret
			changed = true
		}
		// Migrasi cookie_secure: config yang dibuat sebelum v1.1.0 tidak
		// punya kunci ini (nol value = false). Karena default yang aman
		// adalah true, kunci yang hilang dianggap true, bukan false.
		if !bytes.Contains(data, []byte(`"cookie_secure"`)) {
			instance.CookieSecure = true
			changed = true
		}
		if changed {
			_ = Save(path, instance)
		}

		applyEnvOverrides(instance)
		err = checkSecrets(instance)
		if err == nil {
			err = checkWebhookURL(instance)
		}
		if err == nil {
			err = checkExternalSecrets(instance)
		}
		if err == nil {
			err = checkLocalAPI(instance)
		}
	})

	return instance, err
}

// initFreshConfig menangani boot pertama tanpa config.json. Rahasia JWT
// acak HANYA dibuat dan disimpan bila environment TIDAK menyediakan
// FIM_JWT_SECRET (T-07): sebelumnya secret acak selalu ditulis ke disk
// walau env sudah menyediakan secret — meninggalkan secret usang di
// config.json yang bukan secret yang dipakai, dan membingungkan operator
// (serta membuat file config ada padahal deployment 100% env tidak
// membutuhkannya).
func initFreshConfig(instance *Config, path string) error {
	if os.Getenv("FIM_JWT_SECRET") == "" {
		secret, err := generateRandomSecret()
		if err != nil {
			return err
		}
		instance.JWTSecret = secret
		if err := Save(path, instance); err != nil {
			return err
		}
	}
	applyEnvOverrides(instance)
	if err := checkSecrets(instance); err != nil {
		return err
	}
	if err := checkWebhookURL(instance); err != nil {
		return err
	}
	return checkLocalAPI(instance)
}

// applyEnvOverrides menerapkan konfigurasi sensitif dari environment setelah
// file config dibaca. Nilai dari environment TIDAK ditulis balik ke disk,
// sehingga deployment (systemd/Docker) bisa menyimpan rahasia di secret
// manager tanpa meninggalkan salinan plaintext di config.json.
//
// Variabel yang didukung:
//
//	FIM_SERVER_PORT, FIM_JWT_SECRET, FIM_DB_PATH,
//	FIM_ADMIN_USERNAME, FIM_ADMIN_PASSWORD,
//	FIM_AUDITOR_USERNAME, FIM_AUDITOR_PASSWORD,
//	FIM_TELEGRAM_TOKEN, FIM_TELEGRAM_CHAT_ID,
//	FIM_BACKUP_WEBHOOK_URL, FIM_WEBHOOK_SECRET (secret HMAC webhook;
//	tidak pernah ditulis ke config.json),
//	FIM_SCAN_INTERVAL_SEC (30-86400), FIM_WORKER_COUNT (1-16),
//	FIM_ALLOWED_ORIGINS (dipisah koma),
//	FIM_COOKIE_SECURE ("1"/"true" atau "0"/"false")
//
// Yang TIDAK punya env override dan hanya diatur lewat config.json atau
// Settings API: watch_paths dan login_path.
// ApplyEnvOverrides menerapkan override environment ke config (dipakai
// saat boot lewat Load, dan oleh pengujian untuk menandai field yang
// berasal dari environment).
func (c *Config) ApplyEnvOverrides() {
	applyEnvOverrides(c)
}

func applyEnvOverrides(c *Config) {
	if v := os.Getenv("FIM_SERVER_PORT"); v != "" {
		c.ServerPort = v
		markEnv(c, "server_port")
	}
	if v := os.Getenv("FIM_COOKIE_SECURE"); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true":
			c.CookieSecure = true
			markEnv(c, "cookie_secure")
		case "0", "false":
			c.CookieSecure = false
			markEnv(c, "cookie_secure")
		}
	}
	if v := os.Getenv("FIM_JWT_SECRET"); v != "" {
		c.JWTSecret = v
		markEnv(c, "jwt_secret")
	}
	if v := os.Getenv("FIM_DB_PATH"); v != "" {
		c.DBPath = v
		markEnv(c, "db_path")
	}
	if v := os.Getenv("FIM_ADMIN_USERNAME"); v != "" {
		c.AdminUsername = v
		markEnv(c, "admin_username")
	}
	if v := os.Getenv("FIM_ADMIN_PASSWORD"); v != "" {
		c.AdminPassword = hashForMemory(v)
		markEnv(c, "admin_password")
	}
	if v := os.Getenv("FIM_AUDITOR_USERNAME"); v != "" {
		c.AuditorUsername = v
		markEnv(c, "auditor_username")
	}
	if v := os.Getenv("FIM_AUDITOR_PASSWORD"); v != "" {
		c.AuditorPassword = hashForMemory(v)
		markEnv(c, "auditor_password")
	}
	if v := os.Getenv("FIM_TELEGRAM_TOKEN"); v != "" {
		c.TelegramToken = v
		markEnv(c, "telegram_token")
	}
	if v := os.Getenv("FIM_TELEGRAM_CHAT_ID"); v != "" {
		c.TelegramChatID = v
		markEnv(c, "telegram_chat_id")
	}
	if v := os.Getenv("FIM_BACKUP_WEBHOOK_URL"); v != "" {
		c.BackupWebhookURL = v
		markEnv(c, "backup_webhook_url")
	}
	// Secret HMAC webhook: env-only, tidak di-mark sebagai env override
	// karena field ini tidak pernah dipersist (json:"-" di Config dan
	// Snapshot), jadi Persist tidak akan pernah menuliskannya ke disk.
	if v := os.Getenv("FIM_WEBHOOK_SECRET"); v != "" {
		c.WebhookSecret = v
	}
	if v := os.Getenv("FIM_SCAN_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 30 && n <= 86400 {
			c.ScanIntervalSec = n
			markEnv(c, "scan_interval_sec")
		}
	}
	if v := os.Getenv("FIM_WORKER_COUNT"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= 16 {
			c.WorkerCount = n
			markEnv(c, "worker_count")
		}
	}
	if v := os.Getenv("FIM_ALLOWED_ORIGINS"); v != "" {
		origins := make([]string, 0, 4)
		for _, raw := range strings.Split(v, ",") {
			if origin := strings.TrimSpace(raw); origin != "" {
				origins = append(origins, origin)
			}
		}
		c.AllowedOrigins = origins
		markEnv(c, "allowed_origins")
	}
}

// markEnv mencatat field yang berasal dari environment agar Persist tidak
// menulis rahasia deployment ke config.json.
func markEnv(c *Config, key string) {
	if c.envOverrides == nil {
		c.envOverrides = make(map[string]bool)
	}
	c.envOverrides[key] = true
}

func hashForMemory(value string) string {
	if hashed, ok := hashIfPlaintext(value); ok {
		return hashed
	}
	return value
}

func generateRandomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fail-closed: tidak ada nilai fallback yang dapat ditebak. Bila
		// generator acak OS gagal, daemon tidak boleh boot dengan secret
		// yang dikenal publik.
		return "", fmt.Errorf("cannot generate random JWT secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func Save(path string, cfg *Config) error {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return writeConfig(path, cfg)
}

func writeConfig(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "" {
		os.MkdirAll(dir, 0750)
	}

	return os.WriteFile(path, data, 0600)
}

func (c *Config) Persist() error {
	if c.filePath == "" {
		return nil
	}

	snap := c.Snapshot()

	c.mu.RLock()
	envFields := make(map[string]bool, len(c.envOverrides))
	for key := range c.envOverrides {
		envFields[key] = true
	}
	c.mu.RUnlock()

	if len(envFields) == 0 {
		return writeConfig(c.filePath, snap)
	}

	// Field yang berasal dari environment tidak boleh ikut ditulis. Ambil nilai
	// lama dari file (jika ada) agar config.json tetap bisa dibaca saat env
	// dihilangkan; jika file belum ada, field tersebut dihilangkan.
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &merged); err != nil {
		return err
	}

	if disk, err := os.ReadFile(c.filePath); err == nil {
		var onDisk map[string]json.RawMessage
		if json.Unmarshal(disk, &onDisk) == nil {
			for key := range envFields {
				if value, ok := onDisk[key]; ok {
					merged[key] = value
				} else {
					delete(merged, key)
				}
			}
		}
	} else {
		for key := range envFields {
			delete(merged, key)
		}
	}

	return writeConfig(c.filePath, merged)
}

func (c *Config) Update(fn func(*Config)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c)
}

func (c *Config) GetSessionEpoch() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SessionEpoch
}

func (c *Config) GetWatchPaths() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	paths := make([]string, len(c.WatchPaths))
	copy(paths, c.WatchPaths)
	return paths
}

func (c *Config) GetWorkerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WorkerCount
}

func (c *Config) GetScanInterval() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ScanIntervalSec
}

func (c *Config) GetAllowedOrigins() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	origins := make([]string, len(c.AllowedOrigins))
	copy(origins, c.AllowedOrigins)
	return origins
}

// GetExcludeGlobs mengembalikan pola pengecualian (salinan). Nilai nil
// (mis. config.json berisi "exclude_globs": null) dianggap belum diatur
// dan diganti default, agar daemon tidak berjalan tanpa pengecualian
// hanya karena satu kunci null.
func (c *Config) GetExcludeGlobs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ExcludeGlobs == nil {
		return append([]string(nil), DefaultExcludeGlobs...)
	}
	globs := make([]string, len(c.ExcludeGlobs))
	copy(globs, c.ExcludeGlobs)
	return globs
}

func (c *Config) IsAdminConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AdminPassword != ""
}

// Snapshot adalah salinan konsisten seluruh field config. Dipakai oleh
// handler HTTP agar tidak membaca struct yang sedang dimutasi (data race).
type Snapshot struct {
	ServerPort        string   `json:"server_port"`
	JWTSecret         string   `json:"jwt_secret"`
	LoginPath         string   `json:"login_path"`
	CookieSecure      bool     `json:"cookie_secure"`
	MonitoringEnabled bool     `json:"monitoring_enabled"`
	SessionEpoch      int      `json:"session_epoch"`
	WebhookSecret     string   `json:"-"`
	AdminUsername     string   `json:"admin_username"`
	AdminPassword     string   `json:"admin_password"`
	AuditorUsername   string   `json:"auditor_username"`
	AuditorPassword   string   `json:"auditor_password"`
	WatchPaths        []string `json:"watch_paths"`
	ScanIntervalSec   int      `json:"scan_interval_sec"`
	WorkerCount       int      `json:"worker_count"`
	ExcludeGlobs      []string `json:"exclude_globs"`
	TelegramToken     string   `json:"telegram_token"`
	TelegramChatID    string   `json:"telegram_chat_id"`
	// Sumber kredensial Telegram (T-07): true bila nilainya berasal dari
	// environment (fim.env), bukan dari config.json/Settings API. Dipakai
	// GetSettings agar UI bisa menonaktifkan kolom Telegram yang dikelola
	// env, dan UpdateSettings untuk menolak perubahan atasnya.
	TelegramTokenFromEnv  bool     `json:"telegram_token_from_env"`
	TelegramChatIDFromEnv bool     `json:"telegram_chat_id_from_env"`
	BackupWebhookURL      string   `json:"backup_webhook_url"`
	AllowedOrigins        []string `json:"allowed_origins"`
	DBPath                string   `json:"db_path"`
}

func (c *Config) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths := make([]string, len(c.WatchPaths))
	copy(paths, c.WatchPaths)

	origins := make([]string, len(c.AllowedOrigins))
	copy(origins, c.AllowedOrigins)

	// Nilai nil ("exclude_globs": null di config.json) diganti default,
	// sama seperti GetExcludeGlobs, agar API tidak pernah mengembalikan
	// null untuk field ini.
	globs := c.ExcludeGlobs
	if globs == nil {
		globs = DefaultExcludeGlobs
	}
	globsCopy := make([]string, len(globs))
	copy(globsCopy, globs)

	return Snapshot{
		ServerPort:            c.ServerPort,
		JWTSecret:             c.JWTSecret,
		LoginPath:             c.LoginPath,
		CookieSecure:          c.CookieSecure,
		MonitoringEnabled:     c.MonitoringEnabled,
		SessionEpoch:          c.SessionEpoch,
		WebhookSecret:         c.WebhookSecret,
		AdminUsername:         c.AdminUsername,
		AdminPassword:         c.AdminPassword,
		AuditorUsername:       c.AuditorUsername,
		AuditorPassword:       c.AuditorPassword,
		WatchPaths:            paths,
		ScanIntervalSec:       c.ScanIntervalSec,
		WorkerCount:           c.WorkerCount,
		ExcludeGlobs:          globsCopy,
		TelegramToken:         c.TelegramToken,
		TelegramChatID:        c.TelegramChatID,
		TelegramTokenFromEnv:  c.envOverrides["telegram_token"],
		TelegramChatIDFromEnv: c.envOverrides["telegram_chat_id"],
		BackupWebhookURL:      c.BackupWebhookURL,
		AllowedOrigins:        origins,
		DBPath:                c.DBPath,
	}
}

func hashIfPlaintext(value string) (string, bool) {
	if value == "" || isBcryptHash(value) {
		return value, false
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		return value, false
	}
	return string(hashed), true
}

func isBcryptHash(value string) bool {
	return len(value) >= 4 &&
		(value[:4] == "$2a$" || value[:4] == "$2b$" || value[:4] == "$2y$")
}
