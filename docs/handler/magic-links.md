# MagicLinkHandler — Passwordless Login

`MagicLinkHandler` provides passwordless authentication via one-time email links. Tokens expire after 15 minutes and are single-use. If no account exists for the email, one is auto-provisioned on verification.

## Configuration

```go
h := &handler.MagicLinkHandler{
    Users:             userStore,
    MagicLinks:        magicLinkStore,
    JWT:               jwtMgr,
    Sender:            func(ctx context.Context, email, token string) error { /* send email */ return nil },
    CookieName:        "session",
    SecureCookies:     true,
    Sessions:          sessionStore,      // optional
    RefreshTokenTTL:   7 * 24 * time.Hour,
    RefreshCookieName: "refresh",
}
```

## Routes

```
POST /auth/magic-link/request   → h.RequestMagicLink   // send one-time login link
GET  /auth/magic-link/verify    → h.VerifyMagicLink    // ?token=<token> → AuthResponse (HTTP 200)
```

## Response types

`VerifyMagicLink` returns HTTP 200 with the same `AuthResponse` wrapper as `AuthHandler.Login` — `token`, `refresh_token` (when `Sessions` is set), and `user` (`UserDTO`). It also sets an `HttpOnly` session cookie and, when `Sessions` is set and `RefreshCookieName` is non-empty, an `HttpOnly` refresh token cookie. The response also sets `Cache-Control: no-store` and `Pragma: no-cache` to prevent tokens from being stored in browser or proxy caches.

`RequestMagicLink` returns HTTP 200 with:

```json
{"message": "if that email is valid, a login link has been sent"}
```

!!! info "Email enumeration prevention"
    `RequestMagicLink` returns the same success response whether or not the email is registered, preventing enumeration. Validation and operational errors may still surface as non-200 responses.

!!! warning "Sender is required"
    If `Sender` is `nil`, `RequestMagicLink` returns HTTP 503 (`magic link sending is not configured`) without touching the database. Configure `Sender` before mounting this handler in production.

## Session tracking

Session tracking and refresh token rotation work identically to `AuthHandler` — set `Sessions`, `RefreshTokenTTL`, and `RefreshCookieName` to enable them.

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
