package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash dipakai agar percobaan login dengan username tidak dikenal tetap
// memakan waktu bcrypt, sehingga penyerang tidak bisa membedakan username
// valid vs tidak dari timing response.
var dummyHash []byte

func init() {
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("fim-ipl-dummy-password"), bcrypt.DefaultCost)
}

type AuthHandler struct {
	cfg     *config.Config
	ledger  *ledger.Ledger
	setupMu sync.Mutex
}

func NewAuthHandler(cfg *config.Config, l *ledger.Ledger) *AuthHandler {
	return &AuthHandler{cfg: cfg, ledger: l}
}

// parseClaims memvalidasi cookie sesi termasuk denylist logout (jti).
// Ledger boleh nil pada pengujian yang tidak memakai pencabutan token.
func (h *AuthHandler) parseClaims(r *http.Request) (*middleware.Claims, bool) {
	snap := h.cfg.Snapshot()
	return middleware.ParseClaimsWithRevocation(r, snap.JWTSecret, snap.SessionEpoch, func(jti string) bool {
		if h.ledger == nil {
			return false
		}
		return h.ledger.IsTokenRevoked(jti)
	})
}

// truncateLogValue membatasi panjang nilai yang ditulis ke log agar satu
// baris log tidak bisa membengkak sampai 1 MB (batas body request).
func truncateLogValue(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"username and password required"}`, http.StatusBadRequest)
		return
	}

	snap := h.cfg.Snapshot()

	role := ""

	switch {
	case usernameMatches(req.Username, snap.AdminUsername) && snap.AdminPassword != "":
		if verifyPassword(snap.AdminPassword, req.Password) {
			role = middleware.RoleSuperAdmin
		}
	case usernameMatches(req.Username, snap.AuditorUsername) && snap.AuditorPassword != "":
		if verifyPassword(snap.AuditorPassword, req.Password) {
			role = middleware.RoleAuditor
		}
	default:
		// Username tidak dikenal: jalankan bcrypt dummy agar timing seragam.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
	}
	if role == "" {
		// Samakan pesan error agar tidak membocorkan user mana yang valid.
		// Username dan IP dicatat (tanpa password) agar brute force
		// meninggalkan jejak di log untuk insiden response. Username
		// dipotong 64 karakter agar baris log tidak membengkak.
		log.Printf("[Auth] Login failed for user %q from %s", truncateLogValue(req.Username, 64), middleware.ClientIP(r))
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	log.Printf("[Auth] Login succeeded for user %q (role=%s) from %s", truncateLogValue(req.Username, 64), role, middleware.ClientIP(r))

	token, expiresAt, err := middleware.GenerateToken(req.Username, role, snap.JWTSecret, 24, snap.SessionEpoch)
	if err != nil {
		http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// Token TIDAK dikembalikan di body JSON (sejak v1.1.0): ia hanya hidup
	// di cookie HttpOnly agar tidak bisa dibaca JavaScript. Frontend cukup
	// membaca role/username dari respons ini, lalu membuktikan sesi lewat
	// GET /api/v1/auth/me pada setiap refresh halaman.
	middleware.SetSessionCookie(w, token, expiresAt, snap.CookieSecure)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"expires_at": expiresAt,
		"role":       role,
		"username":   req.Username,
	})
}

// Logout menghapus cookie sesi di browser DAN mencabut token itu di sisi
// server (denylist jti, sejak v1.5.0): token yang sudah logout tidak lagi
// bisa dipakai walau belum kedaluwarsa 24 jam. Endpoint ini sengaja tetap
// terproteksi (butuh cookie valid): logout tanpa sesi tidak ada artinya,
// dan frontend selalu membersihkan state lokalnya walau respons ini 401.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Cabut token saat ini sebelum menghapus cookie. Token tanpa jti
	// (diterbitkan sebelum v1.5.0) tidak bisa dicabut satu-per-satu;
	// logout-nya tetap menghapus cookie seperti sebelumnya.
	if claims, ok := h.parseClaims(r); ok && claims.ID != "" && h.ledger != nil {
		expiresAt := time.Now().Add(24 * time.Hour)
		if claims.ExpiresAt != nil {
			expiresAt = claims.ExpiresAt.Time
		}
		if err := h.ledger.RevokeToken(claims.ID, expiresAt); err != nil {
			log.Printf("[Auth] Failed to revoke token on logout: %v", err)
		}
	}

	snap := h.cfg.Snapshot()
	middleware.ClearSessionCookie(w, snap.CookieSecure)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}

// Me mengembalikan identitas pemilik cookie sesi. Ini satu-satunya cara
// frontend mengetahui siapa yang login setelah refresh halaman, karena
// token tidak lagi tersedia di JavaScript.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	claims, ok := h.parseClaims(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":   claims.Username,
		"role":       claims.Role,
		"expires_at": claims.ExpiresAt.Time,
	})
}

// SetupAuditor membuat akun Auditor (read-only). Hanya bisa dipanggil oleh
// Super Admin yang sudah login. Username/password auditor disimpan terpisah
// (bcrypt) agar kredensial manajemen tidak bercampur dengan kredensial admin.
func (h *AuthHandler) SetupAuditor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	h.setupMu.Lock()
	defer h.setupMu.Unlock()

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Bcrypt menolak password >72 byte dengan galat generik; validasi di
	// sini agar klien mendapat 400 yang jelas, bukan 500 "failed to hash".
	username := strings.TrimSpace(req.Username)
	if username == "" || len(req.Password) < 8 || len(req.Password) > 72 {
		http.Error(w, `{"error":"username required and password must be 8-72 characters"}`, http.StatusBadRequest)
		return
	}

	snap := h.cfg.Snapshot()
	if username == snap.AdminUsername {
		http.Error(w, `{"error":"username already taken by admin"}`, http.StatusConflict)
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	// Simpan nilai lama agar gagal persist bisa di-rollback: tanpa ini,
	// memori dan disk berbeda dan percobaan ulang kena 403 karena
	// IsAdminConfigured()/epoch membaca memori.
	old := h.cfg.Snapshot()
	h.cfg.Update(func(c *config.Config) {
		c.AuditorUsername = username
		c.AuditorPassword = string(hashed)
		// Mengganti kredensial membatalkan semua sesi aktif (epoch naik).
		c.SessionEpoch++
	})

	if err := h.cfg.Persist(); err != nil {
		h.cfg.Update(func(c *config.Config) {
			c.AuditorUsername = old.AuditorUsername
			c.AuditorPassword = old.AuditorPassword
			c.SessionEpoch = old.SessionEpoch
		})
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("[Auth] Auditor account created/rotated for user %q; all sessions invalidated (epoch bump)", username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "auditor account created",
	})
}

func verifyPassword(storedPassword, inputPassword string) bool {
	// Fail-closed: hanya hash bcrypt yang diterima. Password plaintext
	// tidak pernah disimpan lagi (Load() memigrasikannya ke bcrypt), jadi
	// jalur fallback plaintext dihapus di v1.4.0 — config yang lolos
	// migrasi tidak boleh bisa login dengan perbandingan plaintext.
	if !isBcryptHash(storedPassword) {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	return err == nil
}

// usernameMatches membandingkan username dalam waktu konstan (lewat hash
// SHA-256 kedua sisi) agar keberadaan username tidak bisa dibedakan dari
// timing perbandingan string `==`.
func usernameMatches(input, stored string) bool {
	if stored == "" {
		return false
	}
	a := sha256.Sum256([]byte(input))
	b := sha256.Sum256([]byte(stored))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func isBcryptHash(s string) bool {
	return len(s) >= 4 && (s[:4] == "$2a$" || s[:4] == "$2b$" || s[:4] == "$2y$")
}

func (h *AuthHandler) SetupPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	h.setupMu.Lock()
	defer h.setupMu.Unlock()

	if h.cfg.IsAdminConfigured() {
		http.Error(w, `{"error":"password already configured"}`, http.StatusForbidden)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Username wajib: username kosong akan menyimpan password tetapi
	// tidak ada username yang bisa login (setup terkunci 403 selamanya).
	// Batas 72 byte karena bcrypt menolak password yang lebih panjang.
	username := strings.TrimSpace(req.Username)
	if username == "" || len(req.Password) < 8 || len(req.Password) > 72 {
		http.Error(w, `{"error":"username required and password must be 8-72 characters"}`, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	// Simpan nilai lama agar gagal persist bisa di-rollback (lihat
	// SetupAuditor): tanpa ini, memori dan disk berbeda dan setup
	// berikutnya kena 403 "password already configured".
	old := h.cfg.Snapshot()
	h.cfg.Update(func(c *config.Config) {
		c.AdminUsername = username
		c.AdminPassword = string(hashedPassword)
		// Mengganti kredensial membatalkan semua sesi aktif (epoch naik).
		c.SessionEpoch++
	})

	if err := h.cfg.Persist(); err != nil {
		h.cfg.Update(func(c *config.Config) {
			c.AdminUsername = old.AdminUsername
			c.AdminPassword = old.AdminPassword
			c.SessionEpoch = old.SessionEpoch
		})
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("[Auth] Super Admin password configured; all sessions invalidated (epoch bump)")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "password configured successfully",
	})
}
