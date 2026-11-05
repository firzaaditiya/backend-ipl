package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-value"

func requestWithToken(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token, Path: "/api/v1"})
	return r
}

func TestParseClaimsRejectsBearerHeader(t *testing.T) {
	// Sejak v1.1.0 header Authorization tidak lagi diterima: satu-satunya
	// pembawa sesi adalah cookie HttpOnly. Token yang dikirim lewat header
	// harus ditolak meskipun tandatangannya valid.
	token, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, ok := ParseClaims(r, testSecret, 0); ok {
		t.Fatal("expected Bearer header to be rejected (cookie-only auth)")
	}
}

func TestGenerateTokenRejectsUnknownRole(t *testing.T) {
	if _, _, err := GenerateToken("root", "admin", testSecret, 1, 0); err == nil {
		t.Fatal("expected error for unknown role")
	}
}

func TestParseClaimsAcceptsValidRoles(t *testing.T) {
	for _, role := range []string{RoleSuperAdmin, RoleAuditor} {
		token, _, err := GenerateToken("user", role, testSecret, 1, 0)
		if err != nil {
			t.Fatalf("GenerateToken(%s): %v", role, err)
		}
		claims, ok := ParseClaims(requestWithToken(token), testSecret, 0)
		if !ok {
			t.Fatalf("expected valid claims for role %s", role)
		}
		if claims.Role != role {
			t.Fatalf("expected role %s, got %s", role, claims.Role)
		}
	}
}

func TestParseClaimsRejectsWrongSecret(t *testing.T) {
	token, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, ok := ParseClaims(requestWithToken(token), "other-secret", 0); ok {
		t.Fatal("expected claims to be rejected with wrong secret")
	}
}

func TestParseClaimsRejectsNonHS256(t *testing.T) {
	claims := Claims{
		Role: RoleSuperAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	signed, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign HS384 token: %v", err)
	}

	if _, ok := ParseClaims(requestWithToken(signed), testSecret, 0); ok {
		t.Fatal("expected HS384 token to be rejected (only HS256 allowed)")
	}
}

func TestParseClaimsRejectsExpiredToken(t *testing.T) {
	token, _, err := GenerateToken("user", RoleAuditor, testSecret, -1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, ok := ParseClaims(requestWithToken(token), testSecret, 0); ok {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestParseClaimsRejectsStaleSessionEpoch(t *testing.T) {
	// Token dari epoch 0 harus ditolak setelah kredensial diubah (epoch 1):
	// inilah yang membatalkan sesi lama saat password diganti.
	token, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, ok := ParseClaims(requestWithToken(token), testSecret, 1); ok {
		t.Fatal("expected token from epoch 0 to be rejected at epoch 1")
	}
	if _, ok := ParseClaims(requestWithToken(token), testSecret, 0); !ok {
		t.Fatal("expected token from epoch 0 to be accepted at epoch 0")
	}
}

func TestParseClaimsAcceptsCurrentSessionEpoch(t *testing.T) {
	token, _, err := GenerateToken("user", RoleAuditor, testSecret, 1, 3)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, ok := ParseClaims(requestWithToken(token), testSecret, 3)
	if !ok {
		t.Fatal("expected token with current epoch to be accepted")
	}
	if claims.SessionEpoch != 3 {
		t.Fatalf("expected session epoch 3, got %d", claims.SessionEpoch)
	}
}

func TestGenerateTokenIncludesJTI(t *testing.T) {
	token, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, ok := ParseClaims(requestWithToken(token), testSecret, 0)
	if !ok {
		t.Fatal("expected valid claims")
	}
	if claims.ID == "" {
		t.Fatal("expected a non-empty jti on every token")
	}
	// Dua token untuk user yang sama harus punya jti berbeda.
	token2, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims2, ok := ParseClaims(requestWithToken(token2), testSecret, 0)
	if !ok {
		t.Fatal("expected valid claims for second token")
	}
	if claims2.ID == claims.ID {
		t.Fatal("two tokens must not share the same jti")
	}
}

func TestParseClaimsWithRevocationRejectsRevokedJTI(t *testing.T) {
	token, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, ok := ParseClaims(requestWithToken(token), testSecret, 0)
	if !ok {
		t.Fatal("expected valid claims")
	}
	revoked := map[string]bool{claims.ID: true}
	isRevoked := func(jti string) bool { return revoked[jti] }

	if _, ok := ParseClaimsWithRevocation(requestWithToken(token), testSecret, 0, isRevoked); ok {
		t.Fatal("revoked token must be rejected")
	}
	// Token lain (jti berbeda) tetap diterima.
	token2, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1, 0)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, ok := ParseClaimsWithRevocation(requestWithToken(token2), testSecret, 0, isRevoked); !ok {
		t.Fatal("non-revoked token must still be accepted")
	}
	// Tanpa checker (nil), token yang dicabut tetap lolos — pemakaian
	// ini hanya untuk jalur yang memang tidak memakai denylist.
	if _, ok := ParseClaimsWithRevocation(requestWithToken(token), testSecret, 0, nil); !ok {
		t.Fatal("nil revocation checker must not reject anything")
	}
}
