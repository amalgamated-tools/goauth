# `auth` package

The `auth` package provides the core primitives used across all goauth flows:

- **[JWT Manager](jwt.md)** — signs and validates HS256 JWTs, derives AES-256-GCM and OIDC HMAC sub-keys
- **[Middleware](middleware.md)** — per-request authentication and authorization middleware
- **[RBAC](rbac.md)** — role-based access control with built-in roles and caching
- **[Rate Limiting](rate-limiting.md)** — per-IP token-bucket limiter
- **[Crypto Utilities](crypto.md)** — hashing, random generation, bcrypt helpers, AES-256-GCM encryption
- **[Store Interfaces](store-interfaces.md)** — database abstractions your application implements
- **[TOTP / MFA](totp.md)** — time-based one-time passwords

## Import path

```go
import "github.com/amalgamated-tools/goauth/auth"
```

## Sentinel errors

| Error | When returned |
|---|---|
| `auth.ErrInvalidToken` | Token signature or structure is invalid |
| `auth.ErrExpiredToken` | Token has passed its `exp` claim |
| `auth.ErrEmailExists` | `CreateUser` called with an already-registered email |
| `auth.ErrEmailNotVerified` | A flow requires a verified email but the account's `EmailVerified` is false |
| `auth.ErrSessionRevoked` | Middleware finds the JWT `jti` in the store but the session is revoked |
| `auth.ErrNotFound` | Store method found no matching record |
| `auth.ErrTOTPNotFound` | `GetTOTPSecret` called for a user who has not enrolled TOTP |
| `auth.ErrInvalidTOTPCode` | TOTP code verification failed |
| `auth.ErrOIDCSubjectAlreadyLinked` | `LinkOIDCSubject` called when the subject is already linked to the user (benign no-op) |
