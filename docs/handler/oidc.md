# OIDCHandler — SSO / OpenID Connect

`OIDCHandler` integrates with any OpenID Connect provider (Google, GitHub, Okta, etc.) using PKCE and provider discovery.

## Configuration

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

Account linking uses a short-lived (5-minute) HMAC-signed state token so the user's browser never sees the user ID in plaintext.

## No refresh tokens

`OIDCHandler` does not have a `Sessions` field and always issues a plain short-lived JWT. If you need server-side session revocation and refresh-token rotation for OIDC logins, implement a custom callback flow that completes the OIDC exchange, creates a session, and issues tokens with the session-aware JWT API (for example, `JWTManager.CreateTokenWithSession`) together with your refresh-token flow.
