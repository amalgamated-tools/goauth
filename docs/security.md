# Security Notes

## Secrets

Pass a secret of at least `auth.MinSecretLength` (32) bytes to `NewJWTManager`. A shorter secret is accepted but not recommended.

## Key material zeroisation

`SecretEncrypter` zeros the HKDF-derived AES key immediately after the block cipher is initialised, reducing the window during which raw key bytes are live in memory.

## API keys

Only the SHA-256 hash of each key is stored. The plaintext key cannot be recovered after the creation response.

## Timing attacks

`AuthHandler.Login` always runs a bcrypt comparison even when the user is not found, preventing username enumeration via timing.

## OIDC PKCE

The OIDC flow uses S256 PKCE and validates the state parameter on every callback.

## Rate limiting

Apply `RateLimiter.Middleware` to login, signup, and passkey endpoints to limit brute-force attempts.

## Cookie security

Set `SecureCookies: true` in production. Auth cookies use `HttpOnly` and `SameSite=Strict`.

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

`RequestMagicLink`, `RequestReset`, and `SendVerification` return the same success response whether or not the email is registered, preventing enumeration via timing or response differences. Validation and operational errors still surface as non-200 responses.
