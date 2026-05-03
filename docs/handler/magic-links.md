# MagicLinkHandler — Passwordless Login

`MagicLinkHandler` provides passwordless authentication via one-time email links. Tokens expire after 15 minutes and are single-use. If no account exists for the email, one is auto-provisioned on verification. The new account uses the email address as the initial display name; users can update their display name afterwards via `AuthHandler.UpdateProfile`.

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
    RefreshTokenTTL:   7 * 24 * time.Hour,
    RefreshCookieName: "refresh",
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
    If `Sender` is `nil`, `RequestMagicLink` returns HTTP 503 (`magic link sending is not configured`) without touching the database. Configure `Sender` before mounting this handler in production.

!!! note "Token retention on email delivery failure"
    If `Sender` returns an error (email delivery fails), `RequestMagicLink` logs the failure server-side but still returns HTTP 200 and **does not delete the stored token**. The token expires naturally after 15 minutes. This is intentional — surfacing delivery failures would allow email enumeration. This differs from `PasswordResetHandler`, which deletes the reset token when `SendResetEmail` fails.

## Session tracking

Session tracking and refresh token rotation work identically to `AuthHandler` — set `Sessions`, `RefreshTokenTTL`, and `RefreshCookieName` to enable them. `RefreshCookieName` is **required** when `Sessions` is set; omitting it causes any `VerifyMagicLink` call to return HTTP 500 `"server misconfiguration"`. See [AuthHandler — Session tracking](auth.md#session-tracking-and-refresh-token-rotation) for details.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `RequestMagicLink` | 200 OK | Always (even if email is unregistered) |
| `RequestMagicLink` | 400 Bad Request | Missing `email` field |
| `RequestMagicLink` | 503 Service Unavailable | `Sender` is `nil` (not configured) |
| `RequestMagicLink` | 500 Internal Server Error | Token generation failure or store failure |
| `VerifyMagicLink` | 200 OK | `AuthResponse` (token + user, plus refresh_token when Sessions is set) |
| `VerifyMagicLink` | 400 Bad Request | Missing `token` query parameter |
| `VerifyMagicLink` | 401 Unauthorized | Invalid, expired, or already-consumed token |
| `VerifyMagicLink` | 500 Internal Server Error | Store failure or user resolution failure |
