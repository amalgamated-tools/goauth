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
token, err := jwtMgr.CreateToken(userID)

// CreateTokenWithSession embeds the session ID as the JWT jti claim.
// Use this (or let AuthHandler do it automatically) when Sessions is enabled.
token, err := jwtMgr.CreateTokenWithSession(userID, sessionID)
```

## Validating tokens

```go
claims, err := jwtMgr.ValidateToken(tokenString)
```

`ValidateToken` returns a `*auth.Claims` value:

```go
type Claims struct {
    jwt.RegisteredClaims // embeds standard JWT fields; Subject is the user ID and ID holds the jti (session ID)
}
```

`claims.Subject` contains the user ID; `claims.ID` (from `jwt.RegisteredClaims`) contains the session ID embedded as the `jti` claim when `CreateTokenWithSession` was used.

`ValidateToken` enforces the following rules and returns a typed error on failure:

| Condition | Error |
|---|---|
| Token is expired | `auth.ErrExpiredToken` |
| `exp` claim is absent | `auth.ErrInvalidToken` |
| Signature is wrong, issuer/audience mismatch, or any other invalid state | `auth.ErrInvalidToken` |

> **Note:** `WithExpirationRequired` is applied during validation, so tokens issued without an `exp` claim are rejected with `ErrInvalidToken`. All tokens produced by `CreateToken` and `CreateTokenWithSession` include `exp`, so this only matters when validating third-party or hand-crafted tokens.

### Parsing without registered-claims validation (logout / audit)

```go
// ParseTokenClaims validates the signature and manually checks iss/aud,
// but skips all other registered-claims validation (expiry, not-before,
// issued-at). Use this in logout or audit flows where the token may already
// be expired or otherwise outside normal time windows.
claims, err := jwtMgr.ParseTokenClaims(tokenString)
```

`ParseTokenClaims` uses `jwt.WithoutClaimsValidation()`, which bypasses **all** registered-claims checks (including `exp`, `nbf`, `iat`, `iss`, and `aud`). The issuer and audience are then re-validated manually, so `ErrInvalidToken` is returned when they do not match. This makes `ParseTokenClaims` safe for extracting the `jti` (session ID) from an expired token in order to revoke the session during logout.

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
