# Crypto Utilities

## Hashing and random generation

```go
// Hash a high-entropy token (e.g. API key) with SHA-256.
tokenHash := auth.HashHighEntropyToken(token)

// Generate n random bytes as lowercase hex.
hex, err := auth.GenerateRandomHex(20) // 40-char hex string

// Generate n random bytes as URL-safe base64.
b64, err := auth.GenerateRandomBase64(32) // 43-char base64url string

// Generate a dummy bcrypt hash for timing-safe "user not found" paths.
dummy := auth.MustGenerateDummyBcryptHash("fallback-secret")

// BcryptCost is the work factor used throughout the library (cost 12).
// Use it when hashing passwords in your own code to stay consistent.
passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
```

## SecretEncrypter (AES-256-GCM)

`SecretEncrypter` is safe for concurrent use. The AES block cipher is initialised once at construction time; `Encrypt` and `Decrypt` each create their own `cipher.AEAD` instance so there is no shared mutable GCM state between goroutines. The raw derived key is zeroed immediately after the cipher is created.

```go
enc, err := jwtMgr.NewSecretEncrypter()

ciphertext, err := enc.Encrypt("sensitive value")
plaintext, err  := enc.Decrypt(ciphertext)
// Decrypt is a no-op if the value doesn't start with the "enc:v1:" prefix.
// Encrypt and Decrypt return an error if called on a zero-value SecretEncrypter.
```

The encrypter is obtained from a `JWTManager` — see [JWT Manager](jwt.md#aes-256-gcm-encryption).
