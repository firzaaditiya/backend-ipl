package middleware

import (
	"errors"
	"net/http"
	"strings"
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

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func ParseClaims(r *http.Request, secret string) (*Claims, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, false
	}

	tokenStr := parts[1]

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
