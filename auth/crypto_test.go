package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHashHighEntropyToken(t *testing.T) {
	h1 := HashHighEntropyToken("token123")
	h2 := HashHighEntropyToken("token123")
	require.Equal(t, h1, h2)

	h3 := HashHighEntropyToken("differenttoken")
	require.NotEqual(t, h1, h3)

	// SHA-256 produces 32 bytes = 64 hex chars.
	require.Len(t, h1, 64)

	// Empty token should still produce a valid hash.
	h4 := HashHighEntropyToken("")
	require.Len(t, h4, 64)
	require.NotEqual(t, h1, h4)
}

func TestGenerateRandomHex(t *testing.T) {
	h1, err := GenerateRandomHex(16)
	require.NoError(t, err)
	// 16 bytes → 32 hex chars.
	require.Len(t, h1, 32)

	h2, err := GenerateRandomHex(16)
	require.NoError(t, err)
	require.NotEqual(t, h1, h2)

	// n=0 should return an empty string without error.
	h3, err := GenerateRandomHex(0)
	require.NoError(t, err)
	require.Empty(t, h3)

	// n=20 → 40 hex chars (used by the API key handler).
	h4, err := GenerateRandomHex(20)
	require.NoError(t, err)
	require.Len(t, h4, 40)
}

func TestMustGenerateDummyBcryptHash(t *testing.T) {
	hash := MustGenerateDummyBcryptHash("some-secret")
	require.NotEmpty(t, hash)
	require.NoError(t, bcrypt.CompareHashAndPassword(hash, []byte("some-secret")))
	// Different password must not match.
	require.Error(t, bcrypt.CompareHashAndPassword(hash, []byte("wrong")))
}

func TestSecretEncrypter_roundtrip(t *testing.T) {
	enc, err := newSecretEncrypter([]byte("test-secret-key-32-bytes-long!!!"))
	require.NoError(t, err)

	plaintext := "hello, world"
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(ciphertext, secretEncryptPrefix))

	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestSecretEncrypter_encryptProducesUniqueValues(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("key"))
	ct1, _ := enc.Encrypt("same-value")
	ct2, _ := enc.Encrypt("same-value")
	// AES-GCM uses a random nonce, so two encryptions of the same plaintext differ.
	require.NotEqual(t, ct1, ct2)
}

func TestSecretEncrypter_emptyString(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("test-key"))

	result, err := enc.Encrypt("")
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestSecretEncrypter_decryptNonPrefixed(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("test-key"))

	// A value that lacks the prefix is returned as-is.
	val := "plain-text-value"
	result, err := enc.Decrypt(val)
	require.NoError(t, err)
	require.Equal(t, val, result)
}

func TestSecretEncrypter_decryptTooShort(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("test-key"))

	// Prefix present but ciphertext body is too short to contain a nonce.
	val := secretEncryptPrefix + "aGVs" // base64 of 3 bytes – shorter than GCM nonce
	_, err := enc.Decrypt(val)
	require.Error(t, err)
}

func TestSecretEncrypter_wrongKey(t *testing.T) {
	enc1, _ := newSecretEncrypter([]byte("key-one"))
	enc2, _ := newSecretEncrypter([]byte("key-two"))

	ciphertext, _ := enc1.Encrypt("secret-data")
	_, err := enc2.Decrypt(ciphertext)
	require.Error(t, err)
}

func TestGenerateRandomBase64_length(t *testing.T) {
	s, err := GenerateRandomBase64(16)
	require.NoError(t, err)
	// 16 bytes encoded as unpadded base64 produce ceiling(16*4/3) = 22 characters.
	require.Len(t, s, 22)
}

func TestGenerateRandomBase64_isRandom(t *testing.T) {
	s1, err := GenerateRandomBase64(32)
	require.NoError(t, err)
	s2, err := GenerateRandomBase64(32)
	require.NoError(t, err)
	require.NotEqual(t, s1, s2)
}

func TestGenerateRandomBase64_isURLSafe(t *testing.T) {
	// Run several times so probability of missing '+' or '/' characters is negligible.
	for i := 0; i < 20; i++ {
		s, err := GenerateRandomBase64(64)
		require.NoError(t, err)
		require.NotContains(t, s, "+", "raw URL-safe base64 must not contain '+'")
		require.NotContains(t, s, "/", "raw URL-safe base64 must not contain '/'")
		require.NotContains(t, s, "=", "raw URL-safe base64 must not contain padding '='")
	}
}

func TestGenerateRandomBase64_zeroBytes(t *testing.T) {
	s, err := GenerateRandomBase64(0)
	require.NoError(t, err)
	require.Empty(t, s)
}
