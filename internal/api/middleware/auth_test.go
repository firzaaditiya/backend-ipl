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
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestGenerateTokenRejectsUnknownRole(t *testing.T) {
	if _, _, err := GenerateToken("root", "admin", testSecret, 1); err == nil {
		t.Fatal("expected error for unknown role")
	}
}

func TestParseClaimsAcceptsValidRoles(t *testing.T) {
	for _, role := range []string{RoleSuperAdmin, RoleAuditor} {
		token, _, err := GenerateToken("user", role, testSecret, 1)
		if err != nil {
			t.Fatalf("GenerateToken(%s): %v", role, err)
		}
		claims, ok := ParseClaims(requestWithToken(token), testSecret)
		if !ok {
			t.Fatalf("expected valid claims for role %s", role)
		}
		if claims.Role != role {
			t.Fatalf("expected role %s, got %s", role, claims.Role)
		}
	}
}

func TestParseClaimsRejectsWrongSecret(t *testing.T) {
	token, _, err := GenerateToken("user", RoleSuperAdmin, testSecret, 1)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, ok := ParseClaims(requestWithToken(token), "other-secret"); ok {
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

	if _, ok := ParseClaims(requestWithToken(signed), testSecret); ok {
		t.Fatal("expected HS384 token to be rejected (only HS256 allowed)")
	}
}

func TestParseClaimsRejectsExpiredToken(t *testing.T) {
	token, _, err := GenerateToken("user", RoleAuditor, testSecret, -1)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, ok := ParseClaims(requestWithToken(token), testSecret); ok {
		t.Fatal("expected expired token to be rejected")
	}
}
