//go:build linux

package fsx

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const openNoFollow = unix.O_NOFOLLOW

// chmodNoFollow mengubah izin berkas tanpa mengikuti symlink: file dibuka
// dengan O_PATH|O_NOFOLLOW (tidak butuh izin baca — bekerja pada file 0600
// milik www-data dengan CAP_FOWNER), lalu chmod dilakukan lewat
// /proc/self/fd/<fd> yang menunjuk inode yang sudah dibuka, bukan path
// yang bisa ditukar penyerang. Pada symlink, chmod lewat fd gagal
// EOPNOTSUPP dan target tidak pernah tersentuh; penolakan symlink eksplisit
// tetap dilakukan Lstat di caller (quarantine.Apply/Release), dan
// verifikasi Lstat sesudahnya mendeteksi penukaran.
//
// Catatan: fchmodat2(2) tidak dipakai karena syscall-nya diblokir (ENOSYS)
// di kernel container VPS ini walau uname melaporkan 6.8.0; fchmod pada fd
// O_PATH juga ditolak kernel (EBADF). Rute /proc ini diverifikasi langsung
// di VPS sebagai user fim-ipl dengan CAP_FOWNER (setara daemon).
func chmodNoFollow(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, unix.O_PATH|openNoFollow, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return os.Chmod(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), mode)
}
