# Security Notes

## Secrets

Pass a secret of at least `auth.MinSecretLength` (32) bytes to `NewJWTManager`. A shorter secret is accepted but not recommended.

## Key material zeroisation

`SecretEncrypter` zeros the HKDF-derived AES key immediately after the block cipher is initialised, reducing the window during which raw key bytes are live in memory.

## API keys

Only the SHA-256 hash of each key is stored. The plaintext key cannot be recovered after the creation response.

## Timing attacks

`AuthHandler.Login` always runs a bcrypt comparison even when the user is not found, preventing username enumeration via timing.

## OIDC duplicate-link guard

`handleLinkCallback` enforces that a single OIDC subject cannot be linked to more than one account, even under database pressure. Any error from `FindByOIDCSubject` that is not `ErrNotFound` (for example a DB timeout) causes an immediate redirect with `oidc_link_error` set to `Link verification failed` **before** `LinkOIDCSubject` is called, and the error is logged via `slog.ErrorContext`. The raw redirect URL may contain the URL-escaped form (for example `oidc_link_error=Link+verification+failed`), but normal query parsing returns the decoded string. The guard is never silently bypassed.

## OIDC PKCE

The OIDC flow uses S256 PKCE and validates the state parameter on every callback.

## Rate limiting

Apply `RateLimiter.Middleware` to login, signup, and passkey endpoints to limit brute-force attempts.

## Cookie security

Set `SecureCookies: true` in production. Auth cookies use `HttpOnly` and `SameSite=Strict`. OIDC flow state cookies use `SameSite=Lax` — required because the provider redirect is a cross-site navigation. See [Cookie Helpers](handler/cookies.md) for details.

## Trusted proxies

If your application runs behind a load balancer, use `NewRateLimiterWithTrustedProxies` and restrict the trusted CIDR list to your actual proxy addresses.

## Session revocation

When `Sessions` is configured, short-lived access tokens (e.g. 15 minutes) are paired with long-lived refresh tokens. Revoking a session (via `SessionHandler.Revoke` or `Logout`) instantly invalidates the bound access token on the next request when the middleware is configured with the same `SessionStore`.

## Refresh token rotation

Each `RefreshToken` call atomically replaces the refresh token. The old token is consumed and cannot be reused, limiting the impact of token theft.

## TOTP replay protection

`TOTPUsedCodeCache` prevents a valid 6-digit code from being accepted twice within the ~90-second validity window. For multi-instance deployments, supplement with a shared external cache.

## Magic links / reset tokens

Raw tokens are never stored; only their SHA-256 hash is persisted. Tokens are one-time use and short-lived (15 min for magic links, 1 h for password resets by default).

## Password reset

Reset tokens are bound to accounts that have a password hash. OIDC-only accounts cannot use the password reset flow.

## Email enumeration

`RequestMagicLink`, `RequestReset`, and `SendVerification` are designed so that, when a request is accepted, the HTTP 200 success response is the same whether or not the email is registered, preventing enumeration via response differences. These endpoints can still return non-200 responses for reasons unrelated to account existence, such as request validation failures (HTTP 400), rate limiting (`RequestReset`, HTTP 429), unconfigured-sender errors (HTTP 503), or internal token-generation / storage failures (`RequestMagicLink` and `RequestReset`, HTTP 500). `SendVerification` intentionally returns 200 even on lookup, token storage, or email send failures to avoid enumeration; only the missing-`email` validation check (400) and an unconfigured `SendEmail` (503) surface as non-200 responses.
