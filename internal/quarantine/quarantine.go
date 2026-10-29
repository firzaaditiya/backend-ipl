// Package quarantine bertanggung jawab untuk melumpuhkan file berbahaya
// yang terdeteksi oleh FIM Engine. Alih-alih menghapus file, permission
// diubah menjadi 000 (chmod 000) sehingga file tetap ada sebagai barang
// bukti forensik tetapi tidak dapat dibaca / dieksekusi oleh siapapun.
//
// Design decision:
//   - Kegagalan chmod bukan sekadar log; caller wajib mengirim notifikasi
//     "URGENT: Quarantine Failed" ke Telegram (dilakukan di layer scanner).
//   - Fungsi Release() memulihkan permission ke 0644 (default file WordPress).
package quarantine

import (
	"errors"
	"fmt"
	"os"
)

// Result menggambarkan hasil upaya karantina.
type Result struct {
	Path       string
	Success    bool
	Err        error
	SkipReason string // diisi jika file di-skip (mis. DELETED)
}

// Apply mencoba menerapkan chmod 000 pada file target.
// Mengembalikan Result yang selalu non-nil.
func Apply(path string) Result {
	res := Result{Path: path}

	// Pakai Lstat agar symlink tidak diikuti: chmod pada symlink berpotensi
	// mengubah permission file di luar watch path.
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			res.SkipReason = "file no longer exists"
			return res
		}
		res.Err = fmt.Errorf("stat: %w", err)
		return res
	}
	if info.Mode()&os.ModeSymlink != 0 {
		res.SkipReason = "target is a symlink"
		return res
	}
	if info.IsDir() {
		res.SkipReason = "target is directory"
		return res
	}

	if err := os.Chmod(path, 0o000); err != nil {
		res.Err = fmt.Errorf("chmod 000: %w", err)
		return res
	}

	res.Success = true
	return res
}

// Release mengembalikan permission file ke 0644 (rw-r--r--) sehingga admin
// bisa memeriksa isi file setelah investigasi selesai.
func Release(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to release symlink target")
	}
	if info.IsDir() {
		return fmt.Errorf("target is a directory")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod 0644: %w", err)
	}
	return nil
}
