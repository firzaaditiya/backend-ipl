package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
)

// SecurityHeaders menambahkan header pertahanan dasar ke setiap respons API.
// HSTS dikirim bila koneksi memang TLS: langsung (r.TLS != nil) atau lewat
// proxy tepercaya yang melaporkan X-Forwarded-Proto: https. Di produksi,
// TLS diakhiri Cloudflare Tunnel lalu diteruskan ke Nginx lewat HTTP, jadi
// r.TLS tidak pernah terisi; sinyalnya adalah header X-Forwarded-Proto
// yang ditulis edge Cloudflare. Header itu hanya dipercaya bila
// FIM_TRUST_PROXY=1 (tanpa itu, siapa pun bisa memalsukannya). Nginx tidak
// menimpa header ini, jadi nilai edge diteruskan apa adanya ke backend.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		if r.TLS != nil || (trustProxy && r.Header.Get("X-Forwarded-Proto") == "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// Recover mengubah panic pada handler menjadi respons 500 JSON yang rapi
// (bukan koneksi yang diputus tanpa keterangan) dan mencatat stack trace.
func Recover(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if logger != nil {
					logger.Printf("[PANIC] %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
