// Package quarantine bertanggung jawab untuk melumpuhkan file berbahaya
// yang terdeteksi oleh FIM Engine. Alih-alih menghapus file, permission
// diubah menjadi 000 (chmod 000) sehingga file tetap ada sebagai barang
// bukti forensik tetapi tidak dapat dibaca / dieksekusi oleh siapapun.
//
// Design decision:
//   - Kegagalan chmod bukan sekadar log; caller wajib mengirim notifikasi
//     "URGENT: Quarantine Failed" ke Telegram (dilakukan di layer scanner).
//   - Apply mencatat permission asli file di Result.OriginalMode; caller
//     menyimpannya (ledger) agar Release bisa mengembalikan permission
//     persis seperti semula, bukan ke default 0644. File yang permission
//     aslinya 0600 atau 0755 harus kembali ke nilai itu setelah
//     investigasi, karena 0644 bisa melonggarkan (0600) atau mengunci
//     (0755) file yang sah.
//   - Fungsi Release() menerima mode target eksplisit; fallback 0644 hanya
//     dipakai caller bila catatan mode asli tidak ditemukan (file yang
//     dikarantina sebelum v1.1.0).
package quarantine

import (
	"errors"
	"fmt"
	"os"
)

// Result menggambarkan hasil upaya karantina.
type Result struct {
	Path         string
	Success      bool
	Err          error
	SkipReason   string      // diisi jika file di-skip (mis. DELETED)
	OriginalMode os.FileMode // permission file SEBELUM chmod 000 (0 bila di-skip)
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

	res.OriginalMode = info.Mode().Perm()

	if err := os.Chmod(path, 0o000); err != nil {
		res.Err = fmt.Errorf("chmod 000: %w", err)
		return res
	}

	res.Success = true
	return res
}

// Release mengembalikan permission file ke mode target (normalnya mode asli
// yang dicatat Apply). Admin bisa memeriksa isi file setelah investigasi
// selesai tanpa mengubah hak aksesnya secara diam-diam.
func Release(path string, mode os.FileMode) error {
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
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %04o: %w", mode, err)
	}
	return nil
}
