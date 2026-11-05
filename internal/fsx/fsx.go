// Package fsx menyediakan operasi file yang aman terhadap symlink
// (TOCTOU antara Lstat dan operasi path). Di Linux, O_NOFOLLOW menolak
// symlink saat open, dan chmod dilakukan lewat /proc/self/fd/<fd> pada
// handle O_PATH|O_NOFOLLOW — menunjuk inode yang sudah dibuka, bukan path
// yang bisa ditukar. Di platform lain, operasi ini jatuh ke perilaku biasa
// dan penolakan symlink ditangani oleh pemeriksaan Lstat di caller.
package fsx

import "os"

// OpenReadNoFollow membuka file untuk dibaca dan menolak symlink (Linux).
func OpenReadNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|openNoFollow, 0)
}

// ChmodNoFollow mengubah izin berkas tanpa mengikuti symlink.
// Implementasi per-platform ada di fsx_linux.go / fsx_other.go.
func ChmodNoFollow(path string, mode os.FileMode) error {
	return chmodNoFollow(path, mode)
}
