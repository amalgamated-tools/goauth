# MagicLinkHandler — Passwordless Login

`MagicLinkHandler` provides passwordless authentication via one-time email links. Tokens expire after 15 minutes by default (configurable via `TokenTTL`) and are single-use. If no account exists for the email, one is auto-provisioned on verification with a blank display name; users can set their display name afterwards via `AuthHandler.UpdateProfile`.

## Configuration

```go
h := &handler.MagicLinkHandler{
    Users:             userStore,
    MagicLinks:        magicLinkStore,
    JWT:               jwtMgr,
    Sender:            func(ctx context.Context, email, token string) error {
        /* compose and send the login email */
        return nil
    },
    CookieName:        "session",
    SecureCookies:     true,
    Sessions:          sessionStore,      // optional
    RefreshTokenTTL:   handler.DefaultRefreshTokenTTL, // default 7 days
    RefreshCookieName: "refresh",
    TokenTTL:          15 * time.Minute,  // optional; defaults to 15 minutes
    // Logger:         nil, // optional; when nil, slog.Default() is resolved at each log site
}

if err := h.Validate(); err != nil {
    log.Fatal(err)
}
```

`Sender` has the named type `handler.MagicLinkSender` (`func(ctx context.Context, email, token string) error`). Pass the raw token (not the hash) directly to the user in a login URL such as `https://myapp.example.com/magic-link?token=<token>`.

## Routes

```
POST /auth/magic-link/request   → h.RequestMagicLink   // send one-time login link
GET  /auth/magic-link/verify    → h.VerifyMagicLink    // ?token=<token> → AuthResponse (HTTP 200)
```

## Response types

`VerifyMagicLink` returns HTTP 200 with the same `AuthResponse` wrapper as `AuthHandler.Login` — `token`, `refresh_token` (when `Sessions` is set), and `user` (`UserDTO`). It also sets an `HttpOnly` session cookie and, when `Sessions` is set, an `HttpOnly` refresh token cookie (via `RefreshCookieName`, which is required when `Sessions` is set). The response also sets `Cache-Control: no-store` and `Pragma: no-cache` to prevent tokens from being stored in browser or proxy caches.

`RequestMagicLink` returns HTTP 200 with:

```json
{"message": "if that email is valid, a login link has been sent"}
```

!!! info "Email enumeration prevention"
    `RequestMagicLink` returns the same success response whether or not the email is registered, preventing enumeration. Validation and operational errors may still surface as non-200 responses.

!!! warning "Sender is required"
    A nil `Sender` is caught by `Validate()` at startup. Configure `Sender` before mounting this handler in production.

!!! note "Token cleanup on email delivery failure"
    If `Sender` returns an error (email delivery fails), `RequestMagicLink` logs the failure server-side, deletes the orphaned token from the store, and still returns HTTP 200. Surfacing delivery failures would allow email enumeration.

## Session tracking

Session tracking and refresh token rotation work identically to `AuthHandler` — set `Sessions`, `RefreshTokenTTL`, and `RefreshCookieName` to enable them. See [AuthHandler — Session tracking](auth.md#session-tracking-and-refresh-token-rotation) for details.

!!! warning "Sessions requires RefreshCookieName"
    When `Sessions` is set, `RefreshCookieName` must also be non-empty. Call `h.Validate()` at server startup to catch this misconfiguration before any `VerifyMagicLink` request reaches token issuance.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `RequestMagicLink` | 200 OK | Always (even if email is unregistered) |
| `RequestMagicLink` | 400 Bad Request | Missing `email` field |
| `RequestMagicLink` | 500 Internal Server Error | Token generation failure or store failure |
| `RequestMagicLink` | 503 Service Unavailable | `Sender` is `nil` (not configured) |
| `VerifyMagicLink` | 200 OK | `AuthResponse` (token + user, plus refresh_token when Sessions is set) |
| `VerifyMagicLink` | 400 Bad Request | Missing `token` query parameter; invalid, expired, or already-consumed token |
| `VerifyMagicLink` | 500 Internal Server Error | Store failure or user resolution failure |

## Observability

`MagicLinkHandler` emits structured log events via `slog` with the request context for trace correlation. Handler-emitted log output — including events emitted during token issuance — goes through the handler's `Logger` field; when `Logger` is `nil`, `slog.Default()` is used. Note that the shared `writeJSON` helper logs JSON encoding failures via the process-wide default logger, independent of this field. To route handler log events to a separate destination, set `Logger` to a `*slog.Logger` backed by the desired handler.

| Event | Level | `slog` message | Endpoint |
|---|---|---|---|
| Token generation failure | `ERROR` | `"failed to generate magic link token"` | `RequestMagicLink` |
| Token persistence store failure | `ERROR` | `"failed to create magic link"` | `RequestMagicLink` |
| Email delivery failure | `ERROR` | `"failed to send magic link email"` | `RequestMagicLink` |
| Orphaned token cleanup failure | `ERROR` | `"failed to delete orphaned magic link"` | `RequestMagicLink` |
| Token lookup store failure | `ERROR` | `"failed to find magic link"` | `VerifyMagicLink` |
| User resolution failure | `ERROR` | `"magic link user resolution failed"` | `VerifyMagicLink` |
| Sessions set without `RefreshCookieName` | `ERROR` | `"issueTokens: Sessions is set but RefreshCookieName is empty — call Validate() at startup"` | `VerifyMagicLink` |
| Refresh token generation failure | `ERROR` | `"failed to generate refresh token"` | `VerifyMagicLink` |
| Session creation store failure | `ERROR` | `"failed to create session"` | `VerifyMagicLink` |
| Access token creation failure | `ERROR` | `"failed to create token"` | `VerifyMagicLink` |

The email delivery failure event is `ERROR`-level but does **not** result in an HTTP 500 — `RequestMagicLink` still returns HTTP 200 to prevent email enumeration.
