package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
)

// BcryptCost is the bcrypt work factor. Cost 12 is stronger than the default 10.
const BcryptCost = 12

// HashHighEntropyToken returns the hex-encoded SHA-256 hash of a high-entropy token.
func HashHighEntropyToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GenerateRandomHex generates n random bytes and returns them as lowercase hex.
func GenerateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateRandomBase64 generates n random bytes and returns them as URL-safe base64.
func GenerateRandomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MustGenerateDummyBcryptHash generates a bcrypt hash for timing-safe comparisons
// when a user is not found.
func MustGenerateDummyBcryptHash(secret string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), BcryptCost)
	if err != nil {
		panic(fmt.Errorf("generate dummy bcrypt hash: %w", err))
	}
	return hash
}

// SecretEncrypter encrypts and decrypts sensitive values using AES-256-GCM.
// The cipher.AEAD returned by cipher.NewGCM is created once at construction
// time and reused across Encrypt/Decrypt calls.
type SecretEncrypter struct {
	gcm cipher.AEAD
}

const secretEncryptPrefix = "enc:v1:"

func newSecretEncrypter(secret []byte) (*SecretEncrypter, error) {
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, secret, nil, []byte("settings-secret-v1"))
	if _, err := r.Read(key); err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return &SecretEncrypter{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (e *SecretEncrypter) Encrypt(plaintext string) (string, error) {
	if e.gcm == nil {
		return "", errors.New("encrypter not initialized")
	}
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return secretEncryptPrefix + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a value previously encrypted by Encrypt.
func (e *SecretEncrypter) Decrypt(value string) (string, error) {
	if e.gcm == nil {
		return "", errors.New("encrypter not initialized")
	}
	if !strings.HasPrefix(value, secretEncryptPrefix) {
		return value, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, secretEncryptPrefix))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("encrypted value too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}
