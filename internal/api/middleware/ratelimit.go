// Package middleware menyediakan komponen HTTP middleware untuk API:
//   - JWT authentication (auth.go)
//   - Token-bucket rate limiter per-IP (ratelimit.go)
package middleware

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// trustProxy hanya aktif jika FIM_TRUST_PROXY=1. Tanpa ini, header
// X-Forwarded-For / X-Real-IP dapat dipalsukan klien untuk melewati limit.
var trustProxy = os.Getenv("FIM_TRUST_PROXY") == "1"

// bucket adalah token-bucket sederhana per IP.
type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter mengimplementasikan token-bucket per-IP.
// Refill rate = capacity / windowSec token per detik.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	refill   float64 // token per detik
	// housekeeping
	lastGC time.Time
}

// NewRateLimiter membuat limiter baru.
// capacity = jumlah request maks dalam window.
// windowSec = panjang window (detik).
//
// Contoh: NewRateLimiter(60, 60) → 60 req/menit per IP dengan burst 60.
func NewRateLimiter(capacity, windowSec int) *RateLimiter {
	if capacity <= 0 {
		capacity = 60
	}
	if windowSec <= 0 {
		windowSec = 60
	}
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		capacity: float64(capacity),
		refill:   float64(capacity) / float64(windowSec),
		lastGC:   time.Now(),
	}
}

// allow memutuskan apakah request dari IP tertentu boleh lewat.
func (rl *RateLimiter) allow(ip string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Housekeeping ringan: setiap 5 menit hapus bucket yang idle > 10 menit.
	if now.Sub(rl.lastGC) > 5*time.Minute {
		for k, b := range rl.buckets {
			if now.Sub(b.lastRefill) > 10*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.lastGC = now
	}

	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{
			tokens:     rl.capacity - 1,
			lastRefill: now,
		}
		return true
	}

	// Refill berdasarkan elapsed time.
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.refill
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// Handler mengembalikan middleware http.Handler yang menerapkan rate limit.
func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Allow adalah versi standalone (dipakai router yang tidak berbasis http.Handler chain).
func (rl *RateLimiter) Allow(r *http.Request) bool {
	return rl.allow(clientIP(r))
}

// ClientIP mengembalikan alamat IP klien dengan aturan trust-proxy yang sama
// seperti rate limiter. Dipakai handler lain (mis. pembatas stream SSE).
func ClientIP(r *http.Request) string {
	return clientIP(r)
}

// clientIP mengekstraksi IP klien dengan preferensi header proxy standar.
func clientIP(r *http.Request) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Ambil IP paling kiri (client asli).
			if idx := strings.Index(xff, ","); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
