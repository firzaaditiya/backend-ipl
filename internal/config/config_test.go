package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashIfPlaintextMigratesPlaintext(t *testing.T) {
	hashed, changed := hashIfPlaintext("admin123")
	if !changed {
		t.Fatal("expected plaintext password to be migrated")
	}
	if !isBcryptHash(hashed) {
		t.Fatalf("expected bcrypt hash, got %q", hashed)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte("admin123")); err != nil {
		t.Fatalf("migrated hash does not match original password: %v", err)
	}
}

func TestHashIfPlaintextIsIdempotent(t *testing.T) {
	first, _ := hashIfPlaintext("secret")
	second, changed := hashIfPlaintext(first)
	if changed {
		t.Fatal("expected already-hashed password to be left untouched")
	}
	if second != first {
		t.Fatal("expected hash to be unchanged on second pass")
	}
}

func TestHashIfPlaintextSkipsEmpty(t *testing.T) {
	if _, changed := hashIfPlaintext(""); changed {
		t.Fatal("expected empty password to be skipped")
	}
}

func TestSnapshotCopiesWatchPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WatchPaths = []string{"/var/www"}

	snap := cfg.Snapshot()
	snap.WatchPaths[0] = "/etc"

	if got := cfg.GetWatchPaths()[0]; got != "/var/www" {
		t.Fatalf("snapshot mutation leaked into config: got %s", got)
	}
}

func TestSnapshotCopiesAllowedOrigins(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowedOrigins = []string{"http://localhost:3000"}

	snap := cfg.Snapshot()
	snap.AllowedOrigins[0] = "http://evil"

	if got := cfg.GetAllowedOrigins()[0]; got != "http://localhost:3000" {
		t.Fatalf("snapshot mutation leaked into config: got %s", got)
	}
}

func TestLoadMigratesAndPersists(t *testing.T) {
	path := t.TempDir() + "/config.json"
	if err := Save(path, &Config{
		ServerPort:    ":9000",
		JWTSecret:     "",
		WatchPaths:    []string{"/srv/www"},
		AdminPassword: "plain",
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.WatchPaths) != 1 || loaded.WatchPaths[0] != "/srv/www" {
		t.Fatalf("watch path not persisted: %v", loaded.WatchPaths)
	}
	if !isBcryptHash(loaded.AdminPassword) {
		t.Fatalf("expected plaintext password migrated on load, got %q", loaded.AdminPassword)
	}
	if loaded.JWTSecret == "" {
		t.Fatal("expected JWT secret to be generated when missing")
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("FIM_SERVER_PORT", ":9999")
	t.Setenv("FIM_JWT_SECRET", "env-secret-value")
	t.Setenv("FIM_ADMIN_PASSWORD", "envpass123")
	t.Setenv("FIM_TELEGRAM_TOKEN", "env-token")
	t.Setenv("FIM_ALLOWED_ORIGINS", "http://a.local, https://b.local")

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.ServerPort != ":9999" {
		t.Fatalf("expected env server port, got %q", cfg.ServerPort)
	}
	if cfg.JWTSecret != "env-secret-value" {
		t.Fatalf("expected env JWT secret, got %q", cfg.JWTSecret)
	}
	if !isBcryptHash(cfg.AdminPassword) {
		t.Fatalf("expected env password hashed in memory, got %q", cfg.AdminPassword)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.AdminPassword), []byte("envpass123")); err != nil {
		t.Fatalf("env password hash mismatch: %v", err)
	}
	if cfg.TelegramToken != "env-token" {
		t.Fatalf("expected env telegram token, got %q", cfg.TelegramToken)
	}
	if len(cfg.AllowedOrigins) != 2 ||
		cfg.AllowedOrigins[0] != "http://a.local" ||
		cfg.AllowedOrigins[1] != "https://b.local" {
		t.Fatalf("unexpected allowed origins: %v", cfg.AllowedOrigins)
	}
}

func TestPersistDoesNotWriteEnvSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, &Config{
		JWTSecret:     "disk-jwt-secret",
		TelegramToken: "disk-telegram-token",
		WatchPaths:    []string{"/var/www"},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	t.Setenv("FIM_JWT_SECRET", "env-jwt-secret")
	t.Setenv("FIM_TELEGRAM_TOKEN", "env-telegram-token")

	cfg := DefaultConfig()
	cfg.filePath = path
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	applyEnvOverrides(cfg)

	cfg.WatchPaths = []string{"/var/www/html"}
	if err := cfg.Persist(); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	var disk map[string]interface{}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after persist: %v", err)
	}
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatalf("Unmarshal after persist: %v", err)
	}

	if got := disk["jwt_secret"]; got != "disk-jwt-secret" {
		t.Fatalf("env JWT secret must not be written to disk, got %v", got)
	}
	if got := disk["telegram_token"]; got != "disk-telegram-token" {
		t.Fatalf("env Telegram token must not be written to disk, got %v", got)
	}
	paths, _ := disk["watch_paths"].([]interface{})
	if len(paths) != 1 || paths[0] != "/var/www/html" {
		t.Fatalf("non-env settings must still be persisted, got %v", disk["watch_paths"])
	}
}
