package config

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/skripsi/fim-ipl/internal/netguard"
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
	// Nilai fallback lama generateRandomSecret (dihapus di v1.4.0): tetap
	// ditolak sebagai jaring pengaman bila config lama masih memakainya.
	"fallback-secret-change-me-immediately",
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

// checkExternalSecrets memastikan file konfigurasi yang berada di disk tidak
// menjadi tempat penyimpanan credential deployment. Menyembunyikan nama file
// tidak membantu bila attacker sudah mendapat shell; memindahkan secret ke
// environment/secret manager dan memisahkan user OS-lah yang memberi batas.
//
// PENTING (bug yang diperbaiki v1.1.0): pemeriksaan ini harus sadar sumber.
// Sebelumnya ia menolak bila field credential TIDAK KOSONG di memori, padahal
// applyEnvOverrides sudah menimpa field itu dengan nilai environment — jadi
// deployment yang 100% memakai environment pun selalu gagal boot. Sekarang
// field yang berasal dari environment (tercatat di envOverrides) diizinkan;
// hanya field yang benar-benar berasal dari config.json yang ditolak.
//
// PENGECUALIAN AUDITOR (T-07): hash bcrypt auditor di config.json
// DIIZINKAN. Auditor dibuat saat runtime lewat API SetupAuditor, dan user
// daemon (fim-ipl) tidak bisa menulis ke fim.env (root:root 0600),
// sehingga memindahkan auditor ke env akan merusak alur setup. Hash bcrypt
// bukan kredensial yang bisa dipakai — tidak bisa ditempel ke form login;
// yang bisa dilakukan penyerang hanyalah brute-force offline, yang
// ditahan oleh biaya bcrypt. Password auditor PLAINTEXT di config.json
// tetap ditolak (migrasi di Load mengubahnya menjadi hash sebelum
// pemeriksaan ini berjalan).
//
// Konsekuensi yang harus dipahami penguji: mode ini TIDAK kompatibel dengan
// penyimpanan Telegram lewat Settings API, karena API itu memang menulis
// ke config.json. Deployment yang memakai Settings API (seperti produksi
// TPQ Al-Fawwaz sebelum T-07) harus mematikan flag ini dan menerima
// config.json (0600, milik fim-ipl) sebagai sumber kebenaran runtime
// untuk Telegram, sementara JWT secret + password admin tetap dari
// fim.env. Sejak langkah produksi T-07, Telegram dikelola lewat fim.env
// dan flag ini aktif di produksi; UpdateSettings menolak perubahan
// Telegram bila sumbernya env (lihat settings.go).
func checkExternalSecrets(c *Config) error {
	if os.Getenv("FIM_REQUIRE_EXTERNAL_SECRETS") != "1" {
		return nil
	}
	fromEnv := func(key string) bool {
		return c.envOverrides != nil && c.envOverrides[key]
	}
	var fields []string
	if c.JWTSecret != "" && !fromEnv("jwt_secret") {
		fields = append(fields, "jwt_secret")
	}
	if c.AdminPassword != "" && !fromEnv("admin_password") {
		fields = append(fields, "admin_password")
	}
	if c.AuditorPassword != "" && !fromEnv("auditor_password") && !isBcryptHash(c.AuditorPassword) {
		fields = append(fields, "auditor_password")
	}
	if c.TelegramToken != "" && !fromEnv("telegram_token") {
		fields = append(fields, "telegram_token")
	}
	if c.TelegramChatID != "" && !fromEnv("telegram_chat_id") {
		fields = append(fields, "telegram_chat_id")
	}
	if len(fields) > 0 {
		return fmt.Errorf("credential fields in config.json are forbidden when FIM_REQUIRE_EXTERNAL_SECRETS=1: %s; use environment/secret manager", strings.Join(fields, ", "))
	}
	return nil
}

func checkLocalAPI(c *Config) error {
	if os.Getenv("FIM_REQUIRE_LOCAL_API") != "1" {
		return nil
	}
	address := strings.ToLower(strings.TrimSpace(c.ServerPort))
	if strings.HasPrefix(address, "127.0.0.1:") || strings.HasPrefix(address, "localhost:") || strings.HasPrefix(address, "[::1]:") {
		return nil
	}
	return fmt.Errorf("server_port must bind to localhost when FIM_REQUIRE_LOCAL_API=1; got %q", c.ServerPort)
}

// checkWebhookURL menolak URL webhook backup yang mengarah ke jaringan
// internal, baik dari config.json maupun dari environment. Validasi yang
// sama juga berjalan di Settings API saat URL disimpan dan di backup
// manager sesaat sebelum pengiriman.
func checkWebhookURL(c *Config) error {
	if c.BackupWebhookURL == "" {
		return nil
	}
	if err := netguard.ValidatePublicURL(c.BackupWebhookURL); err != nil {
		return fmt.Errorf("backup_webhook_url tidak valid: %w", err)
	}
	return nil
}
