# OIDCHandler — SSO / OpenID Connect

`OIDCHandler` integrates with any OpenID Connect provider (Google, GitHub, Okta, etc.) using PKCE and provider discovery.

## Configuration

`NewOIDCHandler` performs OIDC discovery and returns a handler with defaults:

```go
h, err := handler.NewOIDCHandler(
    ctx,
    userStore, jwtMgr,
    "https://accounts.google.com", // OIDC issuer URL (discovery performed at startup)
    clientID, clientSecret,
    "https://myapp.example.com/auth/oidc/callback",
    "session", true,
)
```

To enable server-side session tracking and refresh-token rotation, set the optional fields after construction:

```go
h.Sessions          = sessionStore      // enables session tracking and refresh tokens
h.RefreshCookieName = "refresh"         // required when Sessions is set
h.RefreshTokenTTL   = 7 * 24 * time.Hour // defaults to DefaultRefreshTokenTTL when Sessions is set
```

!!! warning "Sessions requires RefreshCookieName"
    If `Sessions` is set but `RefreshCookieName` is empty, `Callback` returns HTTP 500 `server configuration error`. Always set both together.

## Routes

```
GET  /auth/oidc/login                  → h.Login              // redirects to provider
GET  /auth/oidc/callback               → h.Callback           // handles provider redirect
POST /auth/oidc/link-nonce             → h.CreateLinkNonce    // issue nonce for linking (requires auth)
GET  /auth/oidc/link?nonce=<nonce>     → h.Link               // start link flow (requires auth)
```

## Callback behaviour

The callback performs PKCE verification and handles three cases automatically:

- **Existing OIDC subject** → log in
- **Existing email** → link subject and log in
- **New user** → create account

`Callback` does **not** return JSON. On success it sets the JWT in an `HttpOnly` session cookie and redirects the browser to `/?oidc_login=1` (HTTP 302) so that single-page applications can detect a completed OIDC login via the query parameter.

!!! info "Custom post-login redirect"
    The redirect destination is currently fixed to `/?oidc_login=1`. Frontends that need a custom post-login URL should rely on the `oidc_login=1` query parameter (or another explicit non-`HttpOnly` signal) to trigger navigation, rather than attempting to read the session cookie from browser JavaScript.

## Account linking

Account linking uses a short-lived (5-minute) HMAC-signed state token to protect the integrity of the linking flow. The state value is signed, not encrypted, so any embedded user identifier should be treated as visible to the browser and other parties that can inspect the redirect URL or related cookies.

## Session tracking and refresh tokens

When `Sessions` is set on `OIDCHandler`:

- `Callback` creates a server-side session, embeds the session ID as the JWT `jti` claim, and sets a refresh-token `HttpOnly` cookie (named by `RefreshCookieName`).
- The refresh token is also returned in the redirect body for clients that need it.
- `RefreshTokenTTL` controls refresh-token lifetime; it defaults to `handler.DefaultRefreshTokenTTL` (7 days) when not set.
- Pass `auth.Config{Sessions: sessionStore}` to `auth.Middleware` so that revoked sessions are rejected on every subsequent request.

When `Sessions` is `nil`, `Callback` issues a short-lived access JWT only — no refresh token is created, and token lifetime is determined solely by the configured `JWTManager` TTL.
