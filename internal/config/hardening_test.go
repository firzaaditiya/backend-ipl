package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckSecretsRejectsWeakWhenStrict(t *testing.T) {
	t.Setenv("FIM_STRICT_SECRETS", "1")
	c := &Config{JWTSecret: "change-this-secret-in-production"}
	err := checkSecrets(c)
	if err == nil {
		t.Fatal("rahasia lemah harus menghentikan startup saat FIM_STRICT_SECRETS=1")
	}
	if !strings.Contains(err.Error(), "startup dihentikan") {
		t.Fatalf("pesan error tidak jelas: %v", err)
	}
}

func TestCheckSecretsAcceptsStrongSecret(t *testing.T) {
	t.Setenv("FIM_STRICT_SECRETS", "1")
	c := &Config{JWTSecret: strings.Repeat("a1B2c3D4", 6)}
	if err := checkSecrets(c); err != nil {
		t.Fatalf("rahasia kuat ditolak: %v", err)
	}
}

func TestCheckSecretsWarnsOnlyByDefault(t *testing.T) {
	t.Setenv("FIM_STRICT_SECRETS", "")
	c := &Config{JWTSecret: "short"}
	if err := checkSecrets(c); err != nil {
		t.Fatalf("mode default hanya memberi peringatan, got error: %v", err)
	}
}

func TestHardenFileModeTightensGroupWorldBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("izin Unix tidak berlaku di Windows")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := hardenFileMode(path); err != nil {
		t.Fatalf("hardenFileMode: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("izin = %o, want 600", info.Mode().Perm())
	}
}

func TestCheckExternalSecretsRejectsDiskCredentials(t *testing.T) {
	t.Setenv("FIM_REQUIRE_EXTERNAL_SECRETS", "1")
	c := &Config{
		JWTSecret:      "disk-secret",
		AdminPassword:  "bcrypt-hash",
		TelegramToken:  "bot-token",
		TelegramChatID: "123",
	}
	if err := checkExternalSecrets(c); err == nil {
		t.Fatal("credential di config harus ditolak dalam mode external secrets")
	}
}

func TestCheckExternalSecretsAllowsEnvCredentials(t *testing.T) {
	// Regresi v1.1.0: deployment yang seluruh kredensialnya dari environment
	// sebelumnya selalu gagal boot karena pemeriksaan lama tidak membedakan
	// sumber nilai (disk vs environment).
	t.Setenv("FIM_REQUIRE_EXTERNAL_SECRETS", "1")
	c := &Config{
		JWTSecret:      "env-secret",
		AdminPassword:  "env-hash",
		TelegramToken:  "env-token",
		TelegramChatID: "123",
		envOverrides: map[string]bool{
			"jwt_secret": true, "admin_password": true,
			"telegram_token": true, "telegram_chat_id": true,
		},
	}
	if err := checkExternalSecrets(c); err != nil {
		t.Fatalf("credential dari environment seharusnya diizinkan: %v", err)
	}
}

func TestCheckExternalSecretsRejectsMixedSources(t *testing.T) {
	t.Setenv("FIM_REQUIRE_EXTERNAL_SECRETS", "1")
	c := &Config{
		JWTSecret:     "env-secret",
		TelegramToken: "disk-token",
		envOverrides:  map[string]bool{"jwt_secret": true},
	}
	if err := checkExternalSecrets(c); err == nil {
		t.Fatal("credential dari disk harus tetap ditolak walau sebagian dari env")
	}
	if err := checkExternalSecrets(c); !strings.Contains(err.Error(), "telegram_token") {
		t.Fatalf("pesan harus menyebut field dari disk: %v", err)
	}
}

func TestCheckExternalSecretsAllowsEmptyDiskConfig(t *testing.T) {
	t.Setenv("FIM_REQUIRE_EXTERNAL_SECRETS", "1")
	if err := checkExternalSecrets(&Config{}); err != nil {
		t.Fatalf("config kosong seharusnya diizinkan: %v", err)
	}
}

func TestCheckLocalAPI(t *testing.T) {
	t.Setenv("FIM_REQUIRE_LOCAL_API", "1")
	if err := checkLocalAPI(&Config{ServerPort: "127.0.0.1:8080"}); err != nil {
		t.Fatalf("localhost API ditolak: %v", err)
	}
	if err := checkLocalAPI(&Config{ServerPort: ":8080"}); err == nil {
		t.Fatal("API wildcard harus ditolak dalam mode local-only")
	}
}
