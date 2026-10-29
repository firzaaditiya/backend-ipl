package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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

	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`

	// Auditor adalah role read-only (manajemen/kepala yayasan).
	// Kosong = belum dibuat; dibuat oleh Super Admin via POST /api/v1/setup/auditor.
	AuditorUsername string `json:"auditor_username"`
	AuditorPassword string `json:"auditor_password"`

	WatchPaths      []string `json:"watch_paths"`
	ScanIntervalSec int      `json:"scan_interval_sec"`
	WorkerCount     int      `json:"worker_count"`

	TelegramToken  string `json:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id"`

	BackupWebhookURL string `json:"backup_webhook_url"`

	// AllowedOrigins membatasi CORS. Kosong = izinkan semua origin (perilaku
	// lama, aman karena auth memakai bearer token, bukan cookie). Isi daftar
	// origin (mis. http://localhost:3000) untuk membatasinya.
	AllowedOrigins []string `json:"allowed_origins"`

	DBPath string `json:"db_path"`
}

var (
	instance *Config
	once     sync.Once
)

func DefaultConfig() *Config {
	return &Config{
		ServerPort:      ":8080",
		JWTSecret:       "",
		LoginPath:       "/api/v1/secure-gate",
		AdminUsername:   "",
		AdminPassword:   "",
		WatchPaths:      []string{},
		ScanIntervalSec: 300,
		WorkerCount:     4,
		TelegramToken:   "",
		TelegramChatID:  "",
		DBPath:          "./data/fim.db",
	}
}

func Load(path string) (*Config, error) {
	var err error
	once.Do(func() {
		instance = DefaultConfig()
		instance.filePath = path

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			instance.JWTSecret = generateRandomSecret()
			err = Save(path, instance)
			applyEnvOverrides(instance)
			if secretErr := checkSecrets(instance); secretErr != nil && err == nil {
				err = secretErr
			}
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
			instance.JWTSecret = generateRandomSecret()
			changed = true
		}
		if changed {
			_ = Save(path, instance)
		}

		applyEnvOverrides(instance)
		err = checkSecrets(instance)
	})

	return instance, err
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
//	FIM_ALLOWED_ORIGINS (dipisah koma)
func applyEnvOverrides(c *Config) {
	if v := os.Getenv("FIM_SERVER_PORT"); v != "" {
		c.ServerPort = v
		markEnv(c, "server_port")
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

func generateRandomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "fallback-secret-change-me-immediately"
	}
	return hex.EncodeToString(b)
}

func Get() *Config {
	return instance
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

func (c *Config) IsAdminConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AdminPassword != ""
}

// Snapshot adalah salinan konsisten seluruh field config. Dipakai oleh
// handler HTTP agar tidak membaca struct yang sedang dimutasi (data race).
type Snapshot struct {
	ServerPort       string   `json:"server_port"`
	JWTSecret        string   `json:"jwt_secret"`
	LoginPath        string   `json:"login_path"`
	AdminUsername    string   `json:"admin_username"`
	AdminPassword    string   `json:"admin_password"`
	AuditorUsername  string   `json:"auditor_username"`
	AuditorPassword  string   `json:"auditor_password"`
	WatchPaths       []string `json:"watch_paths"`
	ScanIntervalSec  int      `json:"scan_interval_sec"`
	WorkerCount      int      `json:"worker_count"`
	TelegramToken    string   `json:"telegram_token"`
	TelegramChatID   string   `json:"telegram_chat_id"`
	BackupWebhookURL string   `json:"backup_webhook_url"`
	AllowedOrigins   []string `json:"allowed_origins"`
	DBPath           string   `json:"db_path"`
}

func (c *Config) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths := make([]string, len(c.WatchPaths))
	copy(paths, c.WatchPaths)

	origins := make([]string, len(c.AllowedOrigins))
	copy(origins, c.AllowedOrigins)

	return Snapshot{
		ServerPort:       c.ServerPort,
		JWTSecret:        c.JWTSecret,
		LoginPath:        c.LoginPath,
		AdminUsername:    c.AdminUsername,
		AdminPassword:    c.AdminPassword,
		AuditorUsername:  c.AuditorUsername,
		AuditorPassword:  c.AuditorPassword,
		WatchPaths:       paths,
		ScanIntervalSec:  c.ScanIntervalSec,
		WorkerCount:      c.WorkerCount,
		TelegramToken:    c.TelegramToken,
		TelegramChatID:   c.TelegramChatID,
		BackupWebhookURL: c.BackupWebhookURL,
		AllowedOrigins:   origins,
		DBPath:           c.DBPath,
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
