package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role-based access control untuk skripsi:
//   - super_admin : akses penuh (setup baseline, settings, quarantine release)
//   - auditor     : read-only (dashboard, ledger, metrics, export, verify)
const (
	RoleSuperAdmin = "super_admin"
	RoleAuditor    = "auditor"
)

// tokenIssuer adalah issuer JWT yang wajib ada di setiap token valid.
const tokenIssuer = "fim-ipl"

// SessionCookieName adalah satu-satunya pembawa sesi. Sejak v1.1.0, JWT
// TIDAK PERNAH dikirim lewat body JSON dan TIDAK PERNAH dibaca dari header
// Authorization: browser menyimpannya sebagai cookie HttpOnly sehingga kode
// JavaScript (termasuk skrip XSS yang lolos) tidak bisa membacanya, dan
// cookie hanya dikirim ke path /api/v1 (bukan ke halaman statis maupun ke
// situs WordPress yang dipantau).
const SessionCookieName = "fim_session"

// SetSessionCookie menulis cookie sesi setelah login berhasil. Atributnya
// adalah jawaban atas dua serangan klasik cookie:
//   - HttpOnly: cookie tidak terekspos ke document.cookie (tahan XSS).
//   - SameSite=Lax: browser tidak mengirim cookie pada POST lintas situs
//     (tahan CSRF dasar); router menambah pemeriksaan Origin untuk mutasi.
//   - Secure: aktif di produksi (domain HTTPS); nonaktif hanya untuk dev
//     HTTP lokal lewat FIM_COOKIE_SECURE=0.
func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/api/v1",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

// ClearSessionCookie menghapus cookie sesi (logout). Atribut Path, Secure,
// dan SameSite harus sama dengan saat cookie dibuat agar browser benar-benar
// menghapusnya, bukan membuat cookie kedua.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/api/v1",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func ParseClaims(r *http.Request, secret string) (*Claims, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}

	tokenStr := cookie.Value

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			// Tolak algoritma selain HS256 (mencegah alg-confusion).
			if token.Method != jwt.SigningMethodHS256 {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
	)

	if err != nil || !token.Valid {
		return nil, false
	}
	// Fail-closed: token tanpa role yang valid tidak boleh dianggap admin.
	if claims.Role != RoleSuperAdmin && claims.Role != RoleAuditor {
		return nil, false
	}
	return claims, true
}

func ValidateRequest(r *http.Request, secret string) bool {
	_, ok := ParseClaims(r, secret)
	return ok
}

func JWTAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !ValidateRequest(r, secret) {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GenerateToken(username, role, secret string, expireHours int) (string, time.Time, error) {
	expiresAt := time.Now().Add(time.Duration(expireHours) * time.Hour)

	// Fail-closed: role harus eksplisit dan valid.
	if role != RoleSuperAdmin && role != RoleAuditor {
		return "", time.Time{}, errors.New("invalid role")
	}

	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    tokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, expiresAt, nil
}
