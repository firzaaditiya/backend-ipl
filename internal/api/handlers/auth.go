package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/config"
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
	setupMu sync.Mutex
}

func NewAuthHandler(cfg *config.Config) *AuthHandler {
	return &AuthHandler{cfg: cfg}
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
	case req.Username != "" && req.Username == snap.AdminUsername && snap.AdminPassword != "":
		if verifyPassword(snap.AdminPassword, req.Password) {
			role = middleware.RoleSuperAdmin
		}
	case req.Username != "" && req.Username == snap.AuditorUsername && snap.AuditorPassword != "":
		if verifyPassword(snap.AuditorPassword, req.Password) {
			role = middleware.RoleAuditor
		}
	default:
		// Username tidak dikenal: jalankan bcrypt dummy agar timing seragam.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
	}
	if role == "" {
		// Samakan pesan error agar tidak membocorkan user mana yang valid.
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, expiresAt, err := middleware.GenerateToken(req.Username, role, snap.JWTSecret, 24)
	if err != nil {
		http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"expires_at": expiresAt,
		"role":       role,
		"username":   req.Username,
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

	if req.Username == "" || len(req.Password) < 8 {
		http.Error(w, `{"error":"username required and password min 8 chars"}`, http.StatusBadRequest)
		return
	}

	snap := h.cfg.Snapshot()
	if req.Username == snap.AdminUsername {
		http.Error(w, `{"error":"username already taken by admin"}`, http.StatusConflict)
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	h.cfg.Update(func(c *config.Config) {
		c.AuditorUsername = req.Username
		c.AuditorPassword = string(hashed)
	})

	if err := h.cfg.Persist(); err != nil {
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "auditor account created",
	})
}

func verifyPassword(storedPassword, inputPassword string) bool {
	if isBcryptHash(storedPassword) {
		err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
		return err == nil
	}
	// Fallback kompatibilitas untuk config yang belum sempat dimigrasi.
	return subtle.ConstantTimeCompare([]byte(storedPassword), []byte(inputPassword)) == 1
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

	if req.Password == "" || len(req.Password) < 8 {
		http.Error(w, `{"error":"password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	h.cfg.Update(func(c *config.Config) {
		if req.Username != "" {
			c.AdminUsername = req.Username
		}
		c.AdminPassword = string(hashedPassword)
	})

	if err := h.cfg.Persist(); err != nil {
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "password configured successfully",
	})
}
