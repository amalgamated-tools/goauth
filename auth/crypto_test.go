package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashHighEntropyToken(t *testing.T) {
	h1 := HashHighEntropyToken("token123")
	h2 := HashHighEntropyToken("token123")
	if h1 != h2 {
		t.Error("same input should produce same hash")
	}

	h3 := HashHighEntropyToken("differenttoken")
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}

	// SHA-256 produces 32 bytes = 64 hex chars.
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}

	// Empty token should still produce a valid hash.
	h4 := HashHighEntropyToken("")
	if len(h4) != 64 {
		t.Errorf("empty-token hash should be 64 chars, got %d", len(h4))
	}
	if h1 == h4 {
		t.Error("different inputs should not collide")
	}
}

func TestGenerateRandomHex(t *testing.T) {
	h1, err := GenerateRandomHex(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 16 bytes → 32 hex chars.
	if len(h1) != 32 {
		t.Errorf("expected 32 hex chars for n=16, got %d", len(h1))
	}

	h2, err := GenerateRandomHex(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 == h2 {
		t.Error("successive calls should produce different values")
	}

	// n=0 should return an empty string without error.
	h3, err := GenerateRandomHex(0)
	if err != nil {
		t.Fatalf("unexpected error for n=0: %v", err)
	}
	if h3 != "" {
		t.Errorf("expected empty string for n=0, got %q", h3)
	}

	// n=20 → 40 hex chars (used by the API key handler).
	h4, err := GenerateRandomHex(20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(h4) != 40 {
		t.Errorf("expected 40 hex chars for n=20, got %d", len(h4))
	}
}

func TestMustGenerateDummyBcryptHash(t *testing.T) {
	hash := MustGenerateDummyBcryptHash("some-secret")
	if len(hash) == 0 {
		t.Error("expected non-empty bcrypt hash")
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("some-secret")); err != nil {
		t.Errorf("hash should match source password: %v", err)
	}
	// Different password must not match.
	if err := bcrypt.CompareHashAndPassword(hash, []byte("wrong")); err == nil {
		t.Error("wrong password should not match")
	}
}

func TestSecretEncrypterRoundtrip(t *testing.T) {
	enc, err := newSecretEncrypter([]byte("test-secret-key-32-bytes-long!!!"))
	if err != nil {
		t.Fatalf("newSecretEncrypter: %v", err)
	}

	plaintext := "hello, world"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ciphertext, secretEncryptPrefix) {
		t.Errorf("ciphertext should have prefix %q", secretEncryptPrefix)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestSecretEncrypterEncryptProducesUniqueValues(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("key"))
	ct1, _ := enc.Encrypt("same-value")
	ct2, _ := enc.Encrypt("same-value")
	// AES-GCM uses a random nonce, so two encryptions of the same plaintext differ.
	if ct1 == ct2 {
		t.Error("successive encryptions of same plaintext should differ")
	}
}

func TestSecretEncrypterEmptyString(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("test-key"))

	result, err := enc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty string: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestSecretEncrypterDecryptNonPrefixed(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("test-key"))

	// A value that lacks the prefix is returned as-is.
	val := "plain-text-value"
	result, err := enc.Decrypt(val)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != val {
		t.Errorf("expected %q unchanged, got %q", val, result)
	}
}

func TestSecretEncrypterDecryptTooShort(t *testing.T) {
	enc, _ := newSecretEncrypter([]byte("test-key"))

	// Prefix present but ciphertext body is too short to contain a nonce.
	val := secretEncryptPrefix + "aGVs" // base64 of 3 bytes – shorter than GCM nonce
	_, err := enc.Decrypt(val)
	if err == nil {
		t.Error("expected error for too-short ciphertext")
	}
}

func TestSecretEncrypterWrongKey(t *testing.T) {
	enc1, _ := newSecretEncrypter([]byte("key-one"))
	enc2, _ := newSecretEncrypter([]byte("key-two"))

	ciphertext, _ := enc1.Encrypt("secret-data")
	_, err := enc2.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}
