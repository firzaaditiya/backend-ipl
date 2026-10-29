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
