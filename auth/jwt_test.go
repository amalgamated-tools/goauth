package auth

import (
	"context"
	"testing"
	"time"
)

func TestNewJWTManagerEmptySecret(t *testing.T) {
	mgr, err := NewJWTManager("", time.Hour, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	// A 32-byte random key should have been generated.
	if len(mgr.secret) != 32 {
		t.Errorf("expected 32-byte generated secret, got %d bytes", len(mgr.secret))
	}
}

func TestNewJWTManagerWithSecret(t *testing.T) {
	secret := "my-32-byte-test-secret-for-jwt!!"
	mgr, err := NewJWTManager(secret, 15*time.Minute, "myapp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.issuer != "myapp" {
		t.Errorf("expected issuer %q, got %q", "myapp", mgr.issuer)
	}
	if mgr.ttl != 15*time.Minute {
		t.Errorf("expected TTL 15m, got %v", mgr.ttl)
	}
}

func TestNewJWTManagerDefaultIssuer(t *testing.T) {
	mgr, err := NewJWTManager("any-secret", time.Hour, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.issuer != "goauth" {
		t.Errorf("expected default issuer %q, got %q", "goauth", mgr.issuer)
	}
}

func TestCreateAndValidateToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	token, err := mgr.CreateToken(ctx, "user123")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token string")
	}

	claims, err := mgr.ValidateToken(ctx, token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "user123" {
		t.Errorf("expected UserID %q, got %q", "user123", claims.UserID)
	}
}

func TestValidateExpiredToken(t *testing.T) {
	ctx := context.Background()
	// Negative TTL produces a token that is immediately expired.
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", -time.Hour, "testapp")

	token, _ := mgr.CreateToken(ctx, "user123")
	_, err := mgr.ValidateToken(ctx, token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err != ErrExpiredToken {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestValidateInvalidToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, err := mgr.ValidateToken(ctx, "this.is.not.a.jwt")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidateWrongAlgorithmToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	// A syntactically valid but RS256-signed token (header claims RS256).
	badToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.invalidsig"
	_, err := mgr.ValidateToken(ctx, badToken)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for wrong algorithm, got %v", err)
	}
}

func TestValidateWrongIssuerToken(t *testing.T) {
	ctx := context.Background()
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "app1")
	mgr2, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "app2")

	token, _ := mgr1.CreateToken(ctx, "user123")
	_, err := mgr2.ValidateToken(ctx, token)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for wrong issuer, got %v", err)
	}
}

func TestHMACSignAndVerify(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig := mgr.HMACSign(data)
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}

	if !mgr.HMACVerify(data, sig) {
		t.Error("signature should verify correctly")
	}

	// Tampered data must not verify.
	if mgr.HMACVerify([]byte("tampered-payload"), sig) {
		t.Error("tampered data should not verify")
	}
}

func TestHMACSignTamperedSignature(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig := mgr.HMACSign(data)

	// Flip the first byte of the signature.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	if mgr.HMACVerify(data, tampered) {
		t.Error("tampered signature should not verify")
	}
}

func TestHMACSignDifferentManagers(t *testing.T) {
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	mgr2, _ := NewJWTManager("other-secret-32-bytes-long-here!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig1 := mgr1.HMACSign(data)
	if mgr2.HMACVerify(data, sig1) {
		t.Error("signature from manager1 should not verify with manager2's key")
	}
}

func TestNewSecretEncrypterFromJWT(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	enc, err := mgr.NewSecretEncrypter()
	if err != nil {
		t.Fatalf("NewSecretEncrypter: %v", err)
	}

	ct, err := enc.Encrypt("my-secret-value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "my-secret-value" {
		t.Errorf("expected %q, got %q", "my-secret-value", pt)
	}
}

func TestTokenHasCorrectClaims(t *testing.T) {
	ctx := context.Background()
	issuer := "my-issuer"
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, issuer)

	tokenStr, _ := mgr.CreateToken(ctx, "user-abc")
	claims, err := mgr.ValidateToken(ctx, tokenStr)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, claims.Issuer)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != issuer {
		t.Errorf("expected audience [%q], got %v", issuer, claims.Audience)
	}
	if claims.UserID != "user-abc" {
		t.Errorf("expected UserID %q, got %q", "user-abc", claims.UserID)
	}
	if claims.ExpiresAt == nil {
		t.Error("expected non-nil ExpiresAt")
	}
	if claims.IssuedAt == nil {
		t.Error("expected non-nil IssuedAt")
	}
}

func TestCreateTokenWithSession(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	tok, err := mgr.CreateTokenWithSession(ctx, "user-xyz", "sess-001")
	if err != nil {
		t.Fatalf("CreateTokenWithSession: %v", err)
	}

	claims, err := mgr.ValidateToken(ctx, tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != "user-xyz" {
		t.Errorf("expected UserID %q, got %q", "user-xyz", claims.UserID)
	}
	if claims.ID != "sess-001" {
		t.Errorf("expected jti %q, got %q", "sess-001", claims.ID)
	}
}

func TestCreateTokenWithSessionEmptySessionID(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	tok, err := mgr.CreateTokenWithSession(ctx, "user-xyz", "")
	if err != nil {
		t.Fatalf("CreateTokenWithSession: %v", err)
	}
	claims, err := mgr.ValidateToken(ctx, tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.ID != "" {
		t.Errorf("expected empty jti, got %q", claims.ID)
	}
}

func TestParseTokenClaimsValid(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	tok, _ := mgr.CreateTokenWithSession(ctx, "user-parse", "sess-parse")
	claims, err := mgr.ParseTokenClaims(tok)
	if err != nil {
		t.Fatalf("ParseTokenClaims: %v", err)
	}
	if claims.UserID != "user-parse" {
		t.Errorf("expected UserID %q, got %q", "user-parse", claims.UserID)
	}
	if claims.ID != "sess-parse" {
		t.Errorf("expected jti %q, got %q", "sess-parse", claims.ID)
	}
}

func TestParseTokenClaimsIgnoresExpiry(t *testing.T) {
	ctx := context.Background()
	// Negative TTL produces a token that is immediately expired.
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", -time.Hour, "testapp")

	tok, _ := mgr.CreateTokenWithSession(ctx, "user-exp", "sess-exp")

	// ValidateToken should reject it.
	_, err := mgr.ValidateToken(ctx, tok)
	if err != ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken from ValidateToken, got %v", err)
	}

	// ParseTokenClaims should still succeed (ignores expiry).
	claims, err := mgr.ParseTokenClaims(tok)
	if err != nil {
		t.Fatalf("ParseTokenClaims should succeed on expired token: %v", err)
	}
	if claims.UserID != "user-exp" {
		t.Errorf("expected UserID %q, got %q", "user-exp", claims.UserID)
	}
	if claims.ID != "sess-exp" {
		t.Errorf("expected jti %q, got %q", "sess-exp", claims.ID)
	}
}

func TestParseTokenClaimsInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, err := mgr.ParseTokenClaims("this.is.not.a.jwt")
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestParseTokenClaimsWrongSignature(t *testing.T) {
	ctx := context.Background()
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	mgr2, _ := NewJWTManager("other-secret-32-bytes-long-here!", time.Hour, "testapp")

	tok, _ := mgr1.CreateToken(ctx, "user-sig")
	_, err := mgr2.ParseTokenClaims(tok)
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for wrong signature, got %v", err)
	}
}

