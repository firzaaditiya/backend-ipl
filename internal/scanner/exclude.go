// Aturan pengecualian pemindaian (T-05, v1.6.0).
//
// Tanpa pengecualian, sistem dapat merusak situsnya sendiri: setiap berkas
// baru yang sah — cache plugin, staging update WordPress, gambar yang
// diunggah — terdeteksi CREATED lalu dikarantina chmod 000. Pengecualian
// ada dua lapis:
//
//  1. exclude_globs (konfigurasi, default "wp-content/cache/**" dan
//     "wp-content/upgrade/**"): path yang cocok dikecualikan SELURUHNYA
//     dari deteksi — apa pun jenis berkasnya. Ini pilihan eksplisit
//     admin, dan karena itu dicatat di ledger (SETTINGS_CHANGED) saat
//     diubah.
//  2. Kebijakan uploads (bawaan, tidak dapat dimatikan): berkas NON-KODE
//     di bawah "wp-content/uploads/**" dikecualikan — gambar, dokumen,
//     media yang diunggah lewat WordPress. Berkas yang menyerupai kode
//     (.php, .php.*, .htaccess, .user.ini, dan sejenisnya — lihat
//     isCodeLike) TETAP dipantau dan dikarantina, karena uploads adalah
//     jalur klasik webshell.
//
// Pengecualian BUKAN blind spot diam-diam: berkas yang dikecualikan
// tetap masuk baseline (jadi terlacak dan tercakup digest baseline),
// dan jumlahnya dihitung per siklus (CompareResult.ExcludedFiles) lalu
// ditampilkan di metrik dan dasbor. Yang tidak terjadi hanyalah event
// dan karantina.
package scanner

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// uploadsPrefix adalah direktori unggahan WordPress, relatif terhadap
// watch root. Kebijakan uploads hanya berlaku untuk path di bawah ini.
const uploadsPrefix = "wp-content/uploads/"

// Exclusions adalah snapshot aturan pengecualian yang dipakai satu siklus
// pemindaian. Nil (atau Exclusions kosong) berarti tidak ada pengecualian.
type Exclusions struct {
	Globs      []string
	WatchPaths []string
}

// IsExcluded mengembalikan true bila path absolut ini dikecualikan dari
// deteksi pada siklus ini — baik oleh exclude_globs maupun oleh kebijakan
// uploads. Path dibandingkan relatif terhadap tiap watch root (bila
// berada di bawahnya) dan juga sebagai path absolut, sehingga admin bisa
// menulis pola relatif ("wp-content/cache/**") maupun absolut
// ("/var/www/html/wp-content/cache/**").
func (e *Exclusions) IsExcluded(absPath string) bool {
	if e == nil {
		return false
	}
	slashPath := filepath.ToSlash(absPath)
	for _, root := range e.WatchPaths {
		rel, err := filepath.Rel(root, absPath)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		relSlash := filepath.ToSlash(rel)
		// Kebijakan uploads: non-kode di bawah wp-content/uploads
		// dikecualikan; berkas yang menyerupai kode tetap dipantau.
		if strings.HasPrefix(relSlash, uploadsPrefix) && !isCodeLike(absPath) {
			return true
		}
		for _, glob := range e.Globs {
			if matchGlob(glob, relSlash) {
				return true
			}
		}
	}
	// Pola absolut (tidak terikat watch root).
	for _, glob := range e.Globs {
		if matchGlob(glob, slashPath) {
			return true
		}
	}
	return false
}

// matchGlob mencocokkan satu pola glob terhadap satu path (keduanya
// memakai "/" sebagai pemisah). Segmen "**" cocok dengan nol atau lebih
// segmen path; segmen lain dicocokkan dengan path.Match ("*", "?", "[..]"
// — tetapi "*" tidak menembus "/"). Pola "wp-content/cache/**" cocok
// dengan berkas langsung di bawah cache maupun di subdirektori yang
// lebih dalam.
func matchGlob(pattern, name string) bool {
	pattern = path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(pattern), "/"))
	name = path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(name), "/"))
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pattern, name []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			// "**" di akhir pola cocok dengan sisa path apa pun (termasuk
			// kosong). Di tengah pola, coba semua panjang yang mungkin.
			if len(pattern) == 1 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pattern[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pattern[0], name[0])
		if err != nil || !ok {
			return false
		}
		pattern = pattern[1:]
		name = name[1:]
	}
	return len(name) == 0
}

// ValidateGlobs memeriksa sintaks setiap pola glob. Pola yang tidak valid
// (mis. kelas karakter "[" yang tidak tertutup) ditolak dengan error yang
// menyebut polanya, agar Settings API bisa menjawab 400 sebelum pola
// tersebut disimpan.
func ValidateGlobs(globs []string) error {
	for _, glob := range globs {
		if glob == "" {
			return errors.New("exclude_globs: pola kosong tidak diizinkan")
		}
		for _, seg := range strings.Split(filepath.ToSlash(glob), "/") {
			if seg == "**" {
				continue
			}
			if _, err := path.Match(seg, ""); err != nil {
				return fmt.Errorf("exclude_globs: pola %q tidak valid: %v", glob, err)
			}
		}
	}
	return nil
}
