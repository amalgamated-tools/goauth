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
| `auth.ErrEmailNotVerified` | Exported sentinel for consuming applications and custom middleware. The built-in `AuthHandler` does **not** return this error — it writes HTTP 403 directly when `RequireVerification` is set and the account's `EmailVerified` is false |
| `auth.ErrSessionRevoked` | Returned by `SessionStore.FindSessionByID` when a session has been explicitly revoked. The middleware treats this identically to `ErrNotFound` and returns HTTP 401 "session expired or revoked" |
| `auth.ErrNotFound` | Store method found no matching record |
| `auth.ErrTOTPNotFound` | `GetTOTPSecret` called for a user who has not enrolled TOTP |
| `auth.ErrInvalidTOTPCode` | TOTP code verification failed |
| `auth.ErrOIDCSubjectAlreadyLinked` | Exported sentinel indicating an OIDC subject is already linked to a user. Suppressed only in the best-effort login path; the interactive link callback treats any non-nil return from `LinkOIDCSubject` as a failure (redirects with `oidc_link_error=Failed+to+link`). Prefer an idempotent upsert returning `nil` over returning this sentinel — see [Store Interfaces](store-interfaces.md#userstore) |
