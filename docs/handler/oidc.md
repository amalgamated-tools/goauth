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

// Validate configuration at startup (returns an error if Sessions is set
// without RefreshCookieName).
if err := h.Validate(); err != nil {
    log.Fatal(err)
}
```

!!! warning "Sessions requires RefreshCookieName"
    When `Sessions` is set, `RefreshCookieName` must also be non-empty. Because `Callback` issues tokens via an HTTP redirect (no response body), the refresh token can only be delivered via an `HttpOnly` cookie. Call `h.Validate()` at server startup (after setting all optional fields) to catch this misconfiguration early — before any users attempt to log in.

## Routes

```
GET  /auth/oidc/login                  → h.Login              // redirects to provider
GET  /auth/oidc/callback               → h.Callback           // handles provider redirect
POST /auth/oidc/link-nonce             → h.CreateLinkNonce    // issue nonce for linking (requires auth)
GET  /auth/oidc/link?nonce=<nonce>     → h.Link               // start link flow (requires auth)
```

## Response types

| Endpoint | HTTP status | Response body |
|---|---|---|
| `Login` | 302 Found | *(redirect to provider — no body)* |
| `Callback` | 302 Found | *(login flow: redirects to `/?oidc_login=1`; link flow: redirects to `/?oidc_linked=true` — no body in either case; JWT and optional refresh token delivered via `HttpOnly` cookies on the login path)* |
| `CreateLinkNonce` | 200 OK | `{"nonce": "<nonce>"}` |
| `Link` | 302 Found | *(redirect to provider — no body)* |

## Callback behaviour

The callback performs PKCE verification and handles three cases automatically:

- **Existing OIDC subject** → log in
- **Existing email** → link subject and log in (best-effort: if `LinkOIDCSubject` fails, the failure is logged as a warning and login still succeeds)
- **New user** → create account

`Callback` does **not** return JSON. On success it sets the JWT in an `HttpOnly` session cookie and redirects the browser to `/?oidc_login=1` (HTTP 302) so that single-page applications can detect a completed OIDC login via the query parameter.

!!! info "Custom post-login redirect"
    The redirect destination is currently fixed to `/?oidc_login=1`. Frontends that need a custom post-login URL should rely on the `oidc_login=1` query parameter (or another explicit non-`HttpOnly` signal) to trigger navigation, rather than attempting to read the session cookie from browser JavaScript.

## Account linking

Account linking uses a short-lived (5-minute) HMAC-signed state token to protect the integrity of the linking flow. The state value is signed, not encrypted, so any embedded user identifier should be treated as visible to the browser and other parties that can inspect the redirect URL or related cookies.

!!! info "Shared nonce storage"
    `OIDCHandler` requires a `LinkNonces auth.OIDCLinkNonceStore` field backed by a **shared external store** (e.g. a database table) for account-linking nonces. In a multi-instance deployment (behind a load balancer), nonces must be readable from every instance that may handle the `/oidc/link?nonce=…` request. When `LinkNonces` is `nil`, `CreateLinkNonce` and `Link` return HTTP 503 `"account linking not configured"`. Register `linkNonceStore.DeleteExpiredLinkNonces` with `maintenance.StartCleanup` to prune stale entries.

### Linking flow error redirects

`handleLinkCallback` redirects to `/?oidc_link_error=<value>` on every failure. The redirect applies `url.QueryEscape` to the value, so the raw URL contains `+`/`%XX` encoding; normal query parsing returns the decoded string. The possible values are:

| `oidc_link_error` value | Cause |
|-------------------------|-------|
| `User not found` | `FindByID` returned `ErrNotFound` for the `linkUserID` encoded in the state — the user no longer exists. |
| `Already linked` | The account already has an OIDC subject attached. |
| `SSO identity linked to another account` | The incoming OIDC subject is already associated with a different account. |
| `Link verification failed` | The user store returned an unexpected error (e.g. a database timeout) while looking up the linking user (`FindByID`) or checking for an existing subject association (`FindByOIDCSubject`). The link is **not** performed. |
| `Failed to link` | `LinkOIDCSubject` returned an error after the duplicate-link check passed. |

!!! warning "DB errors never bypass the link guards"
    A transient database error from `FindByID` (user lookup) or `FindByOIDCSubject` (duplicate-subject check) redirects with `Link verification failed` and returns before any linking operation is attempted. This prevents a single OIDC identity from being silently linked to the wrong account under database pressure. Both error paths are logged server-side via `slog.ErrorContext`.

On success the browser is redirected to `/?oidc_linked=true`.

## Session tracking and refresh tokens

When `Sessions` is set on `OIDCHandler`:

- `Callback` creates a server-side session, embeds the session ID as the JWT `jti` claim, and sets a short-lived access token cookie and an `HttpOnly` refresh token cookie (via `RefreshCookieName`, which is required when `Sessions` is non-nil).
- On subsequent requests, the standard `auth.Middleware` validates the `jti` claim against the session store so that revoked sessions are rejected.
- Setting `RefreshCookieName` causes the refresh token to be delivered via an `HttpOnly` cookie. Because `Callback` performs a redirect, the refresh token is **only** available via the cookie (not in a response body). `RefreshCookieName` is therefore required when `Sessions` is non-nil.

When `Sessions` is `nil`, `OIDCHandler` issues an access JWT only. The token lifetime is determined by the configured `JWTManager` TTL.

## HTTP status codes

`Login` redirects to the OIDC provider on success, but it can return a JSON `500 Internal Server Error` if an early failure occurs before a redirect is possible (for example, when generating the OIDC state). `Callback` sets cookies and redirects on success; it returns JSON errors only when a redirect is not possible (e.g. provider configuration errors before any redirect URL is known).

| Endpoint | Status | Condition |
|---|---|---|
| `Login` | 302 Found | Redirects to OIDC provider |
| `Login` | 500 Internal Server Error | Failed to generate random OIDC state |
| `Callback` | 302 Found | Success — redirects to `/?oidc_login=1` |
| `Callback` | 400 Bad Request | Missing/invalid state cookie, PKCE verifier, or authorization code; missing `sub`/`email` claims |
| `Callback` | 401 Unauthorized | Provider authentication failed; invalid token exchange; invalid `id_token`; unverified OIDC email |
| `Callback` | 500 Internal Server Error | Failed to parse claims, resolve/create user, or issue tokens/session (e.g. refresh token generation, session store creation, or JWT creation) |
| `CreateLinkNonce` | 200 OK | `{"nonce": "..."}` |
| `CreateLinkNonce` | 500 Internal Server Error | Failed to generate nonce or store it |
| `CreateLinkNonce` | 503 Service Unavailable | `LinkNonces` is `nil` |
| `Link` | 302 Found | Redirects to OIDC provider to start the linking flow |
| `Link` | 400 Bad Request | Missing nonce |
| `Link` | 401 Unauthorized | Invalid or expired nonce |
| `Link` | 409 Conflict | Account is already linked to an OIDC identity, or user not found (`ErrNotFound` from `Users.FindByID`) |
| `Link` | 500 Internal Server Error | Failed to initiate OIDC redirect, nonce store error, or DB error when looking up user by ID |
| `Link` | 503 Service Unavailable | `LinkNonces` is `nil` |

!!! info "Link-callback redirects"
    After the OIDC provider returns to `Callback` during a link flow, all outcomes (success and failure) are communicated via redirect query parameters (`oidc_linked=true` or `oidc_link_error=<value>`), never via JSON error responses. See [Linking flow error redirects](#linking-flow-error-redirects) for the possible `oidc_link_error` values.
