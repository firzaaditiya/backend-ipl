package config

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

// Ancaman yang ditangani di file ini: aplikasi berjalan di VPS yang sama dengan
// web yang dipantau. Jika penyerang sudah mengeksekusi kode sebagai user web
// (mis. www-data), file config yang bisa dibaca user tersebut akan membocorkan
// JWT secret (bisa memalsukan token admin), token bot Telegram, dan hash
// password. Pengerasan di sini adalah lapisan kedua; lapisan utama adalah user
// OS terpisah untuk daemon (lihat scripts/fim-ipl.service).

// minJWTSecretLength adalah panjang minimum rahasia JWT (32 byte acak).
const minJWTSecretLength = 32

// knownWeakSecrets berisi nilai contoh yang pernah ada di config pengembangan.
var knownWeakSecrets = []string{
	"change-this-secret-in-production",
	"secret",
	"changeme",
}

// hardenFileMode mempersempit izin file config/DB di Unix menjadi 0600 bila
// masih terbaca grup atau dunia. Di Windows izin dikelola ACL, sehingga tidak
// diubah (os.Chmod di Windows hanya mengubah atribut ReadOnly).
func hardenFileMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("izin %s terlalu longgar (%o) dan gagal diperketat: %w",
			path, info.Mode().Perm(), err)
	}
	log.Printf("[Config] Izin %s (%o) diperketat menjadi 0600", path, info.Mode().Perm())
	return nil
}

// checkSecrets memeriksa kekuatan JWT secret. Secara default hanya memberi
// peringatan agar instalasi lama tetap berjalan. Dengan FIM_STRICT_SECRETS=1
// startup gagal sehingga deployment produksi tidak bisa berjalan dengan rahasia
// lemah.
func checkSecrets(c *Config) error {
	problems := make([]string, 0, 2)

	if len(c.JWTSecret) < minJWTSecretLength {
		problems = append(problems, fmt.Sprintf("jwt_secret kurang dari %d karakter", minJWTSecretLength))
	}
	for _, weak := range knownWeakSecrets {
		if strings.EqualFold(c.JWTSecret, weak) {
			problems = append(problems, "jwt_secret memakai nilai contoh/default")
			break
		}
	}
	if len(problems) == 0 {
		return nil
	}

	msg := "[Config] PERINGATAN KEAMANAN: " + strings.Join(problems, "; ") +
		". Gunakan FIM_JWT_SECRET dari environment/secret manager."
	if os.Getenv("FIM_STRICT_SECRETS") == "1" {
		return fmt.Errorf("%s (FIM_STRICT_SECRETS=1: startup dihentikan)", msg)
	}
	log.Println(msg)
	return nil
}
