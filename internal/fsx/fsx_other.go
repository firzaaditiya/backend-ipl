//go:build !linux

package fsx

import "os"

// Di luar Linux tidak ada O_NOFOLLOW yang portabel di paket syscall Go
// dan tidak ada fchmodat2; chmod jatuh ke perilaku biasa dan penolakan
// symlink ditangani oleh pemeriksaan Lstat di caller.
const openNoFollow = 0

func chmodNoFollow(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
