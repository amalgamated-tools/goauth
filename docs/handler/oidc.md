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

// Optional: enable session tracking and refresh-token rotation.
h.Sessions          = sessionStore
h.RefreshTokenTTL   = handler.DefaultRefreshTokenTTL // default 7 days
h.RefreshCookieName = "refresh"
```

!!! warning "Sessions requires RefreshCookieName"
    When `Sessions` is set, `RefreshCookieName` must also be non-empty. Because `Callback` issues tokens via an HTTP redirect (no response body), the refresh token can only be delivered via an `HttpOnly` cookie. `Callback` returns HTTP 500 and logs an error if `Sessions != nil && RefreshCookieName == ""`.

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

### Linking flow error redirects

`handleLinkCallback` redirects to `/?oidc_link_error=<value>` on every failure. The redirect applies `url.QueryEscape` to the value, so the raw URL contains `+`/`%XX` encoding; normal query parsing returns the decoded string. The possible values are:

| `oidc_link_error` value | Cause |
|-------------------------|-------|
| `User not found` | `FindByID` returned an error for the `linkUserID` encoded in the state (user not found **or** any store error such as a DB timeout). |
| `Already linked` | The account already has an OIDC subject attached. |
| `SSO identity linked to another account` | The incoming OIDC subject is already associated with a different account. |
| `Link verification failed` | The user store returned an unexpected error (e.g. a database timeout) while checking for an existing subject association. The link is **not** performed. |
| `Failed to link` | `LinkOIDCSubject` returned an error after the duplicate-link check passed. |

!!! warning "DB errors never bypass the duplicate-link guard"
    A transient database error from `FindByOIDCSubject` redirects with `Link verification failed` and returns before `LinkOIDCSubject` is called. This prevents a single OIDC identity from being silently linked to multiple accounts under database pressure. The error is also logged server-side via `slog.ErrorContext`.

On success the browser is redirected to `/?oidc_linked=true`.

## Session tracking and refresh tokens

When `Sessions` is set on `OIDCHandler`:

- `Callback` creates a server-side session, embeds the session ID as the JWT `jti` claim, and sets a short-lived access token cookie and an `HttpOnly` refresh token cookie (via `RefreshCookieName`, which is required when `Sessions` is non-nil).
- On subsequent requests, the standard `auth.Middleware` validates the `jti` claim against the session store so that revoked sessions are rejected.
- Setting `RefreshCookieName` causes the refresh token to be delivered via an `HttpOnly` cookie. Because `Callback` performs a redirect, the refresh token is **only** available via the cookie (not in a response body). `RefreshCookieName` is therefore required when `Sessions` is non-nil.

When `Sessions` is `nil`, `OIDCHandler` issues an access JWT only. The token lifetime is determined by the configured `JWTManager` TTL.

## HTTP status codes

`Login` redirects to the OIDC provider and does not return JSON. `Callback` sets cookies and redirects on success; it returns JSON errors only when a redirect is not possible (e.g. provider configuration errors before any redirect URL is known).

| Endpoint | Status | Condition |
|---|---|---|
| `Login` | 302 Found | Redirects to OIDC provider |
| `Login` | 500 Internal Server Error | Failed to generate PKCE state cookie |
| `Callback` | 302 Found | Success — redirects to `/?oidc_login=1` |
| `Callback` | 400 Bad Request | Missing/invalid state cookie, PKCE verifier, or authorization code; missing `sub`/`email` claims |
| `Callback` | 401 Unauthorized | Provider authentication failed; invalid token exchange; invalid `id_token`; unverified OIDC email |
| `Callback` | 500 Internal Server Error | `Sessions != nil && RefreshCookieName == ""`; failed to parse claims or resolve/create user |
| `CreateLinkNonce` | 200 OK | `{"nonce": "..."}` |
| `CreateLinkNonce` | 500 Internal Server Error | Failed to generate nonce |
| `Link` | 302 Found | Redirects to OIDC provider to start the linking flow |
| `Link` | 400 Bad Request | Missing nonce |
| `Link` | 401 Unauthorized | Invalid or expired nonce |
| `Link` | 409 Conflict | Account is already linked to an OIDC identity |
| `Link` | 500 Internal Server Error | Failed to initiate OIDC redirect |

!!! info "Link-callback redirects"
    After the OIDC provider returns to `Callback` during a link flow, all outcomes (success and failure) are communicated via redirect query parameters (`oidc_linked=true` or `oidc_link_error=<value>`), never via JSON error responses. See [Linking flow error redirects](#linking-flow-error-redirects) for the possible `oidc_link_error` values.
