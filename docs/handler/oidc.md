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

// Optional: inject a custom structured logger. When nil, slog.Default() is used.
h.Logger = myLogger

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

## Login flow and CSRF/PKCE protection

Both `Login` and `Link` set three short-lived `HttpOnly` cookies before redirecting the browser to the provider, then validate them when the provider redirects back to `Callback`:

| Cookie | Value | Purpose |
|---|---|---|
| `oidc_state` | base64url-encoded state derived from 32 random bytes (~43 chars, no padding); link flows use a dot-delimited HMAC-signed state token | CSRF token |
| `oidc_verifier` | PKCE code verifier (S256 challenge method) | PKCE replay protection |
| `oidc_nonce` | random 32-byte base64url value; embedded in the authorization URL and verified against the `id_token` `nonce` claim on callback | Nonce replay protection |

Cookie attributes: `Path=/`, `HttpOnly`, `SameSite=Lax`, `MaxAge=300` (5 minutes), `Secure` when `SecureCookies` is `true`.

`Callback` clears all three cookies immediately (by setting `MaxAge=-1`) before processing the authorization code.

!!! tip "Debugging cookie issues"
    If `Callback` returns HTTP 400 `"missing state cookie"`, `"missing PKCE verifier cookie"`, or `"missing OIDC nonce cookie"`, check that your reverse proxy preserves `Set-Cookie` headers from the `Login` / `Link` response and that the `Secure` cookie attribute is not stripped for HTTPS traffic.

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

Concurrent first-login races (two requests creating the same account simultaneously) are handled by retrying the lookup when `CreateOIDCUser` returns `ErrEmailExists`. If the retry still cannot find the user — an extremely rare inconsistent-store outcome (e.g. concurrent deletion or read-after-write lag) — the callback returns HTTP 500 logged as `"OIDC user resolution failed"` with error `"failed to resolve user after race retry: not found"`.

`Callback` does **not** return JSON on success. It sets the JWT in an `HttpOnly` session cookie and redirects the browser to `/?oidc_login=1` (HTTP 302) so that single-page applications can detect a completed OIDC login via the query parameter.

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
| `Login` | 500 Internal Server Error | Failed to generate random OIDC state or nonce |
| `Callback` | 302 Found | Success — redirects to `/?oidc_login=1` |
| `Callback` | 400 Bad Request | Missing/invalid state cookie, PKCE verifier, nonce cookie, or authorization code; missing `sub`/`email` claims |
| `Callback` | 401 Unauthorized | Provider authentication failed; invalid token exchange; invalid `id_token`; nonce mismatch; unverified OIDC email |
| `Callback` | 500 Internal Server Error | Failed to parse claims, resolve/create user, or issue tokens/session (e.g. refresh token generation, session store creation, or JWT creation) |
| `CreateLinkNonce` | 200 OK | `{"nonce": "..."}` |
| `CreateLinkNonce` | 500 Internal Server Error | Failed to generate nonce or store it |
| `CreateLinkNonce` | 503 Service Unavailable | `LinkNonces` is `nil` |
| `Link` | 302 Found | Redirects to OIDC provider to start the linking flow |
| `Link` | 400 Bad Request | Missing nonce |
| `Link` | 401 Unauthorized | Invalid or expired nonce |
| `Link` | 404 Not Found | User not found (`ErrNotFound` from `Users.FindByID`) |
| `Link` | 409 Conflict | Account is already linked to an external identity |
| `Link` | 500 Internal Server Error | Failed to initiate OIDC redirect, nonce store error, or DB error when looking up user by ID |
| `Link` | 503 Service Unavailable | `LinkNonces` is `nil` |

!!! info "Link-callback redirects"
    After the OIDC provider returns to `Callback` during a link flow, all outcomes (success and failure) are communicated via redirect query parameters (`oidc_linked=true` or `oidc_link_error=<value>`), never via JSON error responses. See [Linking flow error redirects](#linking-flow-error-redirects) for the possible `oidc_link_error` values.

## Observability

`OIDCHandler` emits structured log events via `slog` with the request context for trace correlation. All log output goes through the handler's `Logger` field; when `Logger` is `nil`, `slog.Default()` is used. To route `OIDCHandler` log events to a separate destination (e.g. a dedicated handler in a multi-tenant application), set `Logger` to a `*slog.Logger` backed by the desired handler.

| Event | Level | `slog` message | Endpoint |
|---|---|---|---|
| OIDC state generation failure | `ERROR` | `"failed to generate OIDC login state"` | `Login` |
| OIDC nonce generation failure | `ERROR` | `"failed to generate OIDC nonce"` | `Login`, `Link` |
| Authorization code exchange failure | `ERROR` | `"OIDC code exchange failed"` | `Callback` |
| `id_token` verification failure | `ERROR` | `"OIDC id_token verification failed"` | `Callback` |
| `id_token` claims parsing failure | `ERROR` | `"failed to parse OIDC claims"` | `Callback` |
| User resolution / creation failure | `ERROR` | `"OIDC user resolution failed"` | `Callback` |
| Best-effort subject link failure | `WARN` | `"failed to link OIDC subject to email-matched user"` | `Callback` |
| Sessions set without `RefreshCookieName` | `ERROR` | `"issueTokens: Sessions is set but RefreshCookieName is empty — call Validate() at startup"` | `Callback` |
| Refresh token generation failure | `ERROR` | `"failed to generate refresh token"` | `Callback` |
| Session creation store failure | `ERROR` | `"failed to create session"` | `Callback` |
| Access token creation failure | `ERROR` | `"failed to create token"` | `Callback` |
| Nonce generation failure | `ERROR` | `"failed to generate link nonce"` | `CreateLinkNonce` |
| Nonce persistence store failure | `ERROR` | `"failed to store link nonce"` | `CreateLinkNonce` |
| Link state generation failure | `ERROR` | `"failed to generate link state"` (`provider=oidc`) | `Link` |
| Nonce consumption failure | `ERROR` | `"failed to consume link nonce"` | `Link` |
| User lookup failure (link initiation) | `ERROR` | `"failed to look up user during link"` (`provider=oidc`) | `Link` |
| User lookup failure (link callback) | `ERROR` | `"failed to look up user during link"` | `Callback` (link flow) |
| OIDC subject lookup failure (link callback) | `ERROR` | `"failed to look up OIDC subject during link"` | `Callback` (link flow) |
| OIDC subject linking failure | `ERROR` | `"failed to link OIDC subject"` | `Callback` (link flow) |

The `WARN`-level best-effort link event does not produce an HTTP error — login still succeeds. The `"OIDC code exchange failed"` and `"OIDC id_token verification failed"` events are followed by HTTP 401. All other `ERROR`-level events in `Login`, `Callback`, `CreateLinkNonce`, and `Link` are followed by an HTTP 500 response. `ERROR`-level events in the `Callback` link flow are followed by a redirect with `oidc_link_error`.
