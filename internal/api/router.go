package api

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/skripsi/fim-ipl/internal/api/handlers"
	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/backup"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/notifier"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

// maxBodyBytes membatasi ukuran request body agar endpoint mutasi tidak bisa
// dipakai untuk menghabiskan memori (mis. JSON raksasa).
const maxBodyBytes = 1 << 20

// NewRouter membangun HTTP handler untuk seluruh REST API.
// Middleware yang diterapkan (dari luar ke dalam):
//
//	CORS  →  RateLimit  →  CSRF (pemeriksaan Origin untuk mutasi)  →
//	Route matcher  →  JWT cookie (untuk endpoint terproteksi)
//
// Autentikasi sejak v1.1.0 hanya memakai cookie HttpOnly (SameSite=Lax).
// Header Authorization TIDAK lagi diterima, dan CORS tidak lagi
// mengizinkannya, agar tidak ada dua jalur autentikasi yang membingungkan.
// Rate limit default 60 req/menit per-IP dengan burst penuh 60.
func NewRouter(
	cfg *config.Config,
	l *ledger.Ledger,
	s *scanner.Scanner,
	n *notifier.Telegram,
	bm *backup.Manager,
	hub *realtime.Hub,
) http.Handler {
	authHandler := handlers.NewAuthHandler(cfg)
	dashboardHandler := handlers.NewDashboardHandler(l, s)
	ledgerHandler := handlers.NewLedgerHandler(l)
	settingsHandler := handlers.NewSettingsHandler(cfg, l, s, n, bm, hub)
	metricsHandler := handlers.NewMetricsHandler(l)
	maintHandler := handlers.NewMaintenanceHandler(s, l, hub)
	quarantineHandler := handlers.NewQuarantineHandler(cfg, l, hub)
	backupHandler := handlers.NewBackupHandler(bm)
	systemHandler := handlers.NewSystemHandler(cfg, s)
	eventsHandler := handlers.NewEventsHandler(hub, s)

	jwtSecret := cfg.JWTSecret
	loginPath := cfg.LoginPath

	// Token bucket: 60 request / 60 detik per-IP.
	limiter := middleware.NewRateLimiter(60, 60)

	core := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// -------- CORS (allowlist opsional) --------
		origins := cfg.GetAllowedOrigins()
		origin := r.Header.Get("Origin")
		if origin != "" {
			if len(origins) == 0 || originAllowed(origins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
		} else if len(origins) == 0 {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}

		// -------- Rate limit (per-IP) --------
		// Stream SSE berumur panjang dan sering reconnect, jadi tidak dihitung
		// sebagai request biasa agar tidak mengunci klien yang sah.
		if path != "/api/v1/events" && !limiter.Allow(r) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}

		// -------- CSRF: pemeriksaan Origin untuk request mutasi --------
		// Cookie sesi dikirim otomatis oleh browser, jadi endpoint mutasi
		// wajib memastikan request datang dari origin yang sah. SameSite=Lax
		// sudah memblokir POST lintas situs di browser modern; pemeriksaan
		// ini adalah lapis kedua untuk klien yang mengabaikan SameSite.
		// Aturan: lolos bila Origin kosong (curl/alat admin), Origin
		// sama dengan Host request (same-origin lewat proxy), atau Origin
		// ada di allowlist. Bila allowlist kosong (mode lama), pemeriksaan
		// dinonaktifkan — produksi wajib mengisi allowlist.
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			if csrfOriginRejected(r, cfg.GetAllowedOrigins()) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"forbidden: origin not allowed"}`))
				return
			}
		}

		// -------- Public endpoints --------
		if path == "/api/v1/healthz" {
			systemHandler.Health(w, r)
			return
		}
		if path == loginPath {
			authHandler.Login(w, r)
			return
		}
		if path == "/api/v1/setup" {
			authHandler.SetupPassword(w, r)
			return
		}

		if !strings.HasPrefix(path, "/api/v1/") {
			http.NotFound(w, r)
			return
		}

		// -------- JWT cookie + RBAC --------
		claims, ok := middleware.ParseClaims(r, jwtSecret)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		isAuditor := claims.Role == middleware.RoleAuditor

		// Helper: tolak auditor pada endpoint mutasi (read-only enforcement).
		forbidAuditor := func() bool {
			if isAuditor {
				http.Error(w, `{"error":"forbidden: auditor is read-only"}`, http.StatusForbidden)
				return true
			}
			return false
		}

		// -------- Protected routes --------
		switch {
		case path == "/api/v1/dashboard/stats":
			dashboardHandler.GetStats(w, r)
		case path == "/api/v1/dashboard/status":
			dashboardHandler.GetStatus(w, r)

		case path == "/api/v1/ledger/blocks":
			ledgerHandler.GetBlocks(w, r)
		case path == "/api/v1/ledger/verify":
			ledgerHandler.VerifyChain(w, r)
		case path == "/api/v1/ledger/export":
			ledgerHandler.ExportLedger(w, r)

		case path == "/api/v1/metrics":
			metricsHandler.GetMetrics(w, r)

		case path == "/api/v1/system/info":
			systemHandler.GetInfo(w, r)

		case path == "/api/v1/events":
			eventsHandler.Stream(w, r)

		case path == "/api/v1/setup/auditor":
			if forbidAuditor() {
				return
			}
			authHandler.SetupAuditor(w, r)

		case path == "/api/v1/auth/me":
			authHandler.Me(w, r)

		case path == "/api/v1/auth/logout":
			authHandler.Logout(w, r)

		case path == "/api/v1/settings":
			switch r.Method {
			case http.MethodGet:
				settingsHandler.GetSettings(w, r)
			case http.MethodPost:
				if forbidAuditor() {
					return
				}
				settingsHandler.UpdateSettings(w, r)
			default:
				http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			}

		case path == "/api/v1/monitoring/start":
			if forbidAuditor() {
				return
			}
			settingsHandler.StartMonitoring(w, r)
		case path == "/api/v1/monitoring/stop":
			if forbidAuditor() {
				return
			}
			settingsHandler.StopMonitoring(w, r)

		case path == "/api/v1/maintenance/enable":
			if forbidAuditor() {
				return
			}
			maintHandler.Enable(w, r)
		case path == "/api/v1/maintenance/disable":
			if forbidAuditor() {
				return
			}
			maintHandler.Disable(w, r)

		case path == "/api/v1/baseline/init":
			if forbidAuditor() {
				return
			}
			settingsHandler.InitializeBaseline(w, r)
		case path == "/api/v1/baseline/update":
			if forbidAuditor() {
				return
			}
			maintHandler.UpdateBaseline(w, r)

		case path == "/api/v1/quarantine/release":
			if forbidAuditor() {
				return
			}
			quarantineHandler.Release(w, r)

		case path == "/api/v1/backup/run":
			if forbidAuditor() {
				return
			}
			backupHandler.Run(w, r)

		case path == "/api/v1/telegram/test":
			if forbidAuditor() {
				return
			}
			settingsHandler.TestTelegram(w, r)

		default:
			http.NotFound(w, r)
		}
	})

	return middleware.Recover(log.Default(), middleware.SecurityHeaders(core))
}

// csrfOriginRejected memutuskan apakah request mutasi harus ditolak karena
// Origin-nya tidak sah. Lihat penjelasan di NewRouter.
func csrfOriginRejected(r *http.Request, allowed []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || len(allowed) == 0 {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return true
	}
	if parsed.Host == r.Host {
		return false
	}
	return !originAllowed(allowed, origin)
}

// originAllowed membandingkan origin secara case-insensitive dan mengabaikan
// trailing slash agar konfigurasi "http://localhost:3000/" tetap cocok.
func originAllowed(allowed []string, origin string) bool {
	target := strings.TrimRight(strings.ToLower(strings.TrimSpace(origin)), "/")
	for _, o := range allowed {
		if strings.TrimRight(strings.ToLower(strings.TrimSpace(o)), "/") == target {
			return true
		}
	}
	return false
}
