package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skripsi/fim-ipl/internal/api/middleware"
	"github.com/skripsi/fim-ipl/internal/config"
	"github.com/skripsi/fim-ipl/internal/ledger"
	"github.com/skripsi/fim-ipl/internal/models"
	"github.com/skripsi/fim-ipl/internal/netguard"
	"github.com/skripsi/fim-ipl/internal/realtime"
	"github.com/skripsi/fim-ipl/internal/scanner"
)

var (
	errScanBusy = errors.New("a scan cycle is already running")
	errNoFiles  = errors.New("no files were scanned")
)

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// scanAndSaveBaseline menjalankan scan penuh secara eksklusif lalu mengganti
// baseline. Guard TryStartScan mencegah scan manual bertabrakan dengan ticker.
func scanAndSaveBaseline(sc *scanner.Scanner, l *ledger.Ledger) (int, error) {
	if !sc.TryStartScan() {
		return 0, errScanBusy
	}
	defer sc.FinishScan()

	results, err := sc.Scan()
	if err != nil {
		return 0, err
	}

	records := make([]models.FileRecord, 0, len(results))
	now := time.Now()
	for _, sr := range results {
		if sr.Err != nil {
			continue
		}
		records = append(records, models.FileRecord{
			Path: sr.Path,
			Hash: sr.Hash,
			// Mode WAJIB dicatat (T-06): sebelum perbaikan ini, rebuild
			// menulis Mode 0 untuk semua berkas. Siklus berikutnya lalu
			// mengadopsi mode diam-diam (ModeAdoptions), sehingga digest
			// baseline berubah tepat setelah rebuild dan verify-baseline
			// selalu melaporkan mismatch sampai rebuild berikutnya —
			// verifikasi terjadwal tidak pernah bisa menunjukkan "cocok".
			Mode:      sr.Mode,
			Size:      sr.Size,
			ModTime:   sr.ModTime,
			ScannedAt: now,
		})
	}

	if len(records) == 0 {
		return 0, errNoFiles
	}

	if err := l.SaveBaseline(records); err != nil {
		return 0, err
	}
	return len(records), nil
}

func writeBaselineError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errScanBusy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a scan is already running"})
	case errors.Is(err, errNoFiles):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "no files found; check that watch paths exist and contain files",
		})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "baseline operation failed"})
	}
}

// validateWatchPaths membersihkan, men-deduplikasi, dan memastikan setiap
// watch path ada dan berupa direktori. Path disimpan dalam bentuk absolut.
func validateWatchPaths(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))

	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}

		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("invalid watch path %q", path)
		}
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("watch path does not exist or is not a directory: %s", path)
		}

		key := abs
		if runtime.GOOS == "windows" {
			key = strings.ToLower(abs)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, abs)
	}

	if len(out) == 0 {
		return nil, errors.New("at least one watch path is required")
	}
	return out, nil
}

// isPathWithinRoots memastikan target berada di bawah salah satu watch path.
// Dipakai sebelum release karantina agar endpoint tidak bisa chmod file
// sembarang di server. Symlink di-resolve dulu (EvalSymlinks) pada root
// maupun target: tanpa ini, direktori symlink di dalam watch path dapat
// mengarahkan chmod ke file di luar watch path.
func isPathWithinRoots(roots []string, target string) bool {
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	// Target yang tidak ada (mis. sudah dihapus) gagal fail-closed: release
	// terhadap file yang tidak ada memang tidak punya arti.
	targetResolved, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		return false
	}

	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rootResolved, err := filepath.EvalSymlinks(rootAbs)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" {
			rootResolved = strings.ToLower(rootResolved)
			targetResolved = strings.ToLower(targetResolved)
		}

		rel, err := filepath.Rel(rootResolved, targetResolved)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return true
		}
	}
	return false
}

// validateWebhookURL memastikan URL backup webhook valid dan tidak mengarah
// ke jaringan internal. Tanpa pemeriksaan ini, fitur webhook bisa disalahgunakan
// sebagai SSRF (mis. http://169.254.169.254/latest/meta-data di cloud VPS).
// Pemeriksaan dilakukan saat menyimpan DAN sesaat sebelum pengiriman
// (internal/backup), karena DNS dapat berubah di antara kedua momen itu.
func validateWebhookURL(raw string) error {
	return netguard.ValidatePublicURL(raw)
}

// validateOrigins memastikan setiap entry berupa origin (scheme + host[:port])
// tanpa path, mis. "http://localhost:3000".
func validateOrigins(origins []string) ([]string, error) {
	out := make([]string, 0, len(origins))
	for _, raw := range origins {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if value == "*" {
			return nil, errors.New("use '*' is not allowed; an empty list means no cross-origin access (fail-closed)")
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("invalid origin %q (expected scheme://host[:port])", raw)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return nil, fmt.Errorf("origin %q must not contain a path", raw)
		}
		out = append(out, strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/"))
	}
	return out, nil
}

// publishState menyiarkan status monitoring/maintenance ke klien SSE.
func publishState(hub *realtime.Hub, sc *scanner.Scanner, reason string) {
	if hub == nil || sc == nil {
		return
	}
	hub.Publish("status", map[string]interface{}{
		"reason":           reason,
		"is_monitoring":    sc.IsRunning(),
		"maintenance_mode": sc.IsMaintenance(),
	})
}

// ---------------------------------------------------------------------------
// Audit trail aksi administratif (T-03, v1.6.0)
// ---------------------------------------------------------------------------

// actorFromRequest membangun string pelaku dari klaim JWT di cookie sesi:
// "username (Peran) dari IP". Peran ditulis dengan label tampilan agar
// mudah dibaca di Audit Trail ("Super Admin", bukan "super_admin").
// Bila klaim tidak bisa dibaca — tidak mungkin terjadi di endpoint
// terproteksi karena router sudah memvalidasi token — dikembalikan
// "(tidak dikenal)" agar blok tetap tercatat, bukan gagal.
func actorFromRequest(r *http.Request, cfg *config.Config, l *ledger.Ledger) string {
	if cfg == nil {
		return "(tidak dikenal)"
	}
	snap := cfg.Snapshot()
	claims, ok := middleware.ParseClaimsWithRevocation(r, snap.JWTSecret, snap.SessionEpoch, func(jti string) bool {
		if l == nil {
			return false
		}
		return l.IsTokenRevoked(jti)
	})
	if !ok {
		return "(tidak dikenal)"
	}
	role := claims.Role
	switch role {
	case middleware.RoleSuperAdmin:
		role = "Super Admin"
	case middleware.RoleAuditor:
		role = "Auditor"
	}
	return fmt.Sprintf("%s (%s) dari %s", claims.Username, role, middleware.ClientIP(r))
}

// appendAdminBlock mencatat satu aksi administratif ke ledger. Mengikuti
// pola RELEASED: kegagalan pencatatan tidak membatalkan aksi (sudah
// terjadi), tetapi dilaporkan lewat nilai kembalian agar handler bisa
// menampilkannya di respons ("audited": false) dan mencatatnya di log.
//
// Actor diterima sebagai parameter, bukan dibaca dari request di sini:
// handler WAJIB menghitungnya di awal (sebelum mutasi) lewat
// actorFromRequest — tindakan yang menaikkan epoch sesi (mis. mengatur
// auditor) membuat token pemanggil tidak valid lagi, sehingga actor yang
// dibaca sesudah mutasi akan menjadi "(tidak dikenal)".
func appendAdminBlock(l *ledger.Ledger, actor, action, detail string) bool {
	return appendAdminBlockWithDigest(l, actor, action, detail, "", 0)
}

// appendAdminBlockWithDigest sama seperti appendAdminBlock, tetapi
// menyertakan digest baseline (T-04) — dipakai blok BASELINE_INIT dan
// BASELINE_UPDATE.
func appendAdminBlockWithDigest(l *ledger.Ledger, actor, action, detail, digest string, count int) bool {
	if l == nil {
		return false
	}
	if _, err := l.AppendBlock(models.AnomalyEvent{
		FilePath:       models.AdminBlockPath,
		Action:         action,
		Actor:          actor,
		Detail:         detail,
		BaselineDigest: digest,
		BaselineCount:  count,
	}); err != nil {
		log.Printf("[Audit] Failed to record %s block: %v", action, err)
		return false
	}
	return true
}

// maxReasonRunes adalah panjang maksimum alasan wajib (pelepasan karantina
// dan baseline/update): cukup untuk satu kalimat yang jelas, dan alasan
// tersimpan permanen di ledger sehingga tidak boleh membengkak.
const maxReasonRunes = 500

// parseReason membaca alasan wajib dari body JSON {"reason": "..."}.
// Alasan 1–500 karakter setelah trim; kosong, terlalu panjang, atau body
// yang tidak bisa dibaca ditolak.
func parseReason(r *http.Request) (string, bool) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", false
	}
	return validateReason(req.Reason)
}

// validateReason memeriksa satu alasan: 1–500 karakter setelah trim.
func validateReason(reason string) (string, bool) {
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > maxReasonRunes {
		return "", false
	}
	return reason, true
}
