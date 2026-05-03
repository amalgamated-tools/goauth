# JWT Manager

`JWTManager` signs and validates HS256 JWTs. It also derives an OIDC HMAC sub-key and an AES-256-GCM encryption key from the same secret, so a single secret value covers all cryptographic needs.

## Construction

```go
jwtMgr, err := auth.NewJWTManager(secret, ttl, issuer)
// secret  – signing secret (empty → random, tokens won't survive restarts)
// ttl     – token lifetime (e.g. 24 * time.Hour)
// issuer  – value used for iss/aud claims (defaults to "goauth")
```

Pass a secret of at least `auth.MinSecretLength` (32) bytes. A shorter secret is accepted but not recommended.

## Creating tokens

```go
token, err := jwtMgr.CreateToken(ctx, userID)

// CreateTokenWithSession embeds the session ID as the JWT jti claim.
// Use this (or let AuthHandler do it automatically) when Sessions is enabled.
token, err := jwtMgr.CreateTokenWithSession(ctx, userID, sessionID)
```

## Validating tokens

```go
claims, err := jwtMgr.ValidateToken(ctx, tokenString)
// claims.UserID contains the subject (sub); claims.ID contains the session ID (jti)
```

### Parsing without time checks

```go
// ParseTokenClaims validates the signature (and iss/aud) but ignores all
// time-based claim validation (expiry, not-before, issued-at).
// Useful for logout or audit flows that need the session ID from a token
// that may be expired, not yet valid, or otherwise outside time-based checks.
claims, err := jwtMgr.ParseTokenClaims(tokenString)
```

## HMAC signing

`HMACSign` and `HMACVerify` use an OIDC-derived sub-key for creating and verifying HMAC-SHA256 signatures. Useful for custom flows that need a MAC tied to the JWT secret (e.g. signed redirect state) without exposing the raw secret.

```go
data := []byte("example payload")
sig := jwtMgr.HMACSign(data)
ok := jwtMgr.HMACVerify(data, sig)
```

## AES-256-GCM encryption

```go
encrypter, err := jwtMgr.NewSecretEncrypter() // AES-256-GCM, derived from JWT secret
```

See [Crypto Utilities](crypto.md#secretencrypter-aes-256-gcm) for full usage.
