package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewJWTManagerEmptySecret(t *testing.T) {
	mgr, err := NewJWTManager("", time.Hour, "test")
	require.NoError(t, err)
	require.NotNil(t, mgr)
	// A 32-byte random key should have been generated.
	require.Len(t, mgr.secret, 32)
}

func TestNewJWTManagerWithSecret(t *testing.T) {
	secret := "my-32-byte-test-secret-for-jwt!!"
	mgr, err := NewJWTManager(secret, 15*time.Minute, "myapp")
	require.NoError(t, err)
	require.Equal(t, "myapp", mgr.issuer)
	require.Equal(t, 15*time.Minute, mgr.ttl)
}

func TestNewJWTManagerDefaultIssuer(t *testing.T) {
	mgr, err := NewJWTManager("any-secret", time.Hour, "")
	require.NoError(t, err)
	require.Equal(t, "goauth", mgr.issuer)
}

func TestCreateAndValidateToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	token, err := mgr.CreateToken(ctx, "user123")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := mgr.ValidateToken(ctx, token)
	require.NoError(t, err)
	require.Equal(t, "user123", claims.UserID)
}

func TestValidateExpiredToken(t *testing.T) {
	ctx := context.Background()
	// Negative TTL produces a token that is immediately expired.
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", -time.Hour, "testapp")

	token, _ := mgr.CreateToken(ctx, "user123")
	_, err := mgr.ValidateToken(ctx, token)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredToken)
}

func TestValidateInvalidToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, err := mgr.ValidateToken(ctx, "this.is.not.a.jwt")
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateWrongAlgorithmToken(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	// A syntactically valid but RS256-signed token (header claims RS256).
	badToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.invalidsig"
	_, err := mgr.ValidateToken(ctx, badToken)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateWrongIssuerToken(t *testing.T) {
	ctx := context.Background()
	mgr1, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "app1")
	mgr2, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "app2")

	token, _ := mgr1.CreateToken(ctx, "user123")
	_, err := mgr2.ValidateToken(ctx, token)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestHMACSignAndVerify(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig := mgr.HMACSign(data)
	require.NotEmpty(t, sig)

	require.True(t, mgr.HMACVerify(data, sig))

	// Tampered data must not verify.
	require.False(t, mgr.HMACVerify([]byte("tampered-payload"), sig))
}

func TestHMACSignTamperedSignature(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	data := []byte("test-payload")
	sig := mgr.HMACSign(data)

	// Flip the first byte of the signature.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	require.False(t, mgr.HMACVerify(data, tampered))
}

func TestHMACSignDifferentManagers(t *testing.T) {
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

func TestTokenHasCorrectClaims(t *testing.T) {
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
