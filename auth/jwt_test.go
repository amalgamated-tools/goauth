package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewJWTManager_emptySecret(t *testing.T) {
	mgr, err := NewJWTManager("", time.Hour, "test")
	require.NoError(t, err)
	require.NotNil(t, mgr)
	// A 32-byte random key should have been generated.
	require.Len(t, mgr.secret, 32)
}

func TestNewJWTManager_withSecret(t *testing.T) {
	secret := "my-32-byte-test-secret-for-jwt!!"
	mgr, err := NewJWTManager(secret, 15*time.Minute, "myapp")
	require.NoError(t, err)
	require.Equal(t, "myapp", mgr.issuer)
	require.Equal(t, 15*time.Minute, mgr.ttl)
}

func TestNewJWTManager_defaultIssuer(t *testing.T) {
	mgr, err := NewJWTManager("any-secret", time.Hour, "")
	require.NoError(t, err)
	require.Equal(t, "goauth", mgr.issuer)
}

func TestCreateToken_andValidate(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	token, err := mgr.CreateToken(ctx, "user123")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := mgr.ValidateToken(ctx, token)
	require.NoError(t, err)
	require.Equal(t, "user123", claims.UserID)
}

func TestValidate_expiredToken(t *testing.T) {
	ctx := context.Background()
	// Negative TTL produces a token that is immediately expired.
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", -time.Hour, "testapp")

	token, _ := mgr.CreateToken(ctx, "user123")
	_, err := mgr.ValidateToken(ctx, token)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredToken)
}

func TestValidate_invalidToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, err := mgr.ValidateToken(ctx, "this.is.not.a.jwt")
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidate_wrongAlgorithmToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	// A syntactically valid but RS256-signed token (header claims RS256).
	badToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.invalidsig"
	_, err := mgr.ValidateToken(ctx, badToken)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidate_wrongIssuerToken(t *testing.T) {
	ctx := context.Background()
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "app1")
	mgr2, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "app2")

	token, _ := mgr1.CreateToken(ctx, "user123")
	_, err := mgr2.ValidateToken(ctx, token)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestHMACSign_andVerify(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig := mgr.HMACSign(data)
	require.NotEmpty(t, sig)

	require.True(t, mgr.HMACVerify(data, sig))

	// Tampered data must not verify.
	require.False(t, mgr.HMACVerify([]byte("tampered-payload"), sig))
}

func TestHMACSign_tamperedSignature(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig := mgr.HMACSign(data)

	// Flip the first byte of the signature.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	require.False(t, mgr.HMACVerify(data, tampered))
}

func TestHMACSign_differentManagers(t *testing.T) {
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	mgr2, _ := NewJWTManager("other-secret-32-bytes-long-here!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig1 := mgr1.HMACSign(data)
	require.False(t, mgr2.HMACVerify(data, sig1))
}

func TestNewSecretEncrypterFromJWT(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	enc, err := mgr.NewSecretEncrypter()
	require.NoError(t, err)

	ct, err := enc.Encrypt("my-secret-value")
	require.NoError(t, err)

	pt, err := enc.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, "my-secret-value", pt)
}

func TestToken_hasCorrectClaims(t *testing.T) {
	ctx := context.Background()
	issuer := "my-issuer"
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, issuer)

	tokenStr, _ := mgr.CreateToken(ctx, "user-abc")
	claims, err := mgr.ValidateToken(ctx, tokenStr)
	require.NoError(t, err)
	require.Equal(t, issuer, claims.Issuer)
	require.NotEmpty(t, claims.Audience)
	require.Equal(t, issuer, claims.Audience[0])
	require.Equal(t, "user-abc", claims.UserID)
	require.NotNil(t, claims.ExpiresAt)
	require.NotNil(t, claims.IssuedAt)
}

func TestCreateToken_withSession(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	tok, err := mgr.CreateTokenWithSession(ctx, "user-xyz", "sess-001")
	require.NoError(t, err)

	claims, err := mgr.ValidateToken(ctx, tok)
	require.NoError(t, err)
	require.Equal(t, "user-xyz", claims.UserID)
	require.Equal(t, "sess-001", claims.ID)
}

func TestCreateToken_withSessionEmptySessionID(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	tok, err := mgr.CreateTokenWithSession(ctx, "user-xyz", "")
	require.NoError(t, err)
	claims, err := mgr.ValidateToken(ctx, tok)
	require.NoError(t, err)
	require.Empty(t, claims.ID)
}

func TestParseTokenClaims_valid(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	tok, _ := mgr.CreateTokenWithSession(ctx, "user-parse", "sess-parse")
	claims, err := mgr.ParseTokenClaims(tok)
	require.NoError(t, err)
	require.Equal(t, "user-parse", claims.UserID)
	require.Equal(t, "sess-parse", claims.ID)
}

func TestParseTokenClaims_ignoresExpiry(t *testing.T) {
	ctx := context.Background()
	// Negative TTL produces a token that is immediately expired.
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", -time.Hour, "testapp")

	tok, _ := mgr.CreateTokenWithSession(ctx, "user-exp", "sess-exp")

	// ValidateToken should reject it.
	_, err := mgr.ValidateToken(ctx, tok)
	require.ErrorIs(t, err, ErrExpiredToken)

	// ParseTokenClaims should still succeed (ignores expiry).
	claims, err := mgr.ParseTokenClaims(tok)
	require.NoError(t, err)
	require.Equal(t, "user-exp", claims.UserID)
	require.Equal(t, "sess-exp", claims.ID)
}

func TestParseTokenClaims_invalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, err := mgr.ParseTokenClaims("this.is.not.a.jwt")
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestParseTokenClaims_wrongSignature(t *testing.T) {
	ctx := context.Background()
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	mgr2, _ := NewJWTManager("other-secret-32-bytes-long-here!", time.Hour, "testapp")

	tok, _ := mgr1.CreateToken(ctx, "user-sig")
	_, err := mgr2.ParseTokenClaims(tok)
	require.ErrorIs(t, err, ErrInvalidToken)
}
