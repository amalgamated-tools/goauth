# AuthHandler — Email / Password

`AuthHandler` provides complete email/password authentication: signup, login, logout, token refresh, profile read and update, and password change.

## Configuration

```go
h := &handler.AuthHandler{
    Users:               userStore,
    JWT:                 jwtMgr,
    CookieName:          "session",
    SecureCookies:       true,
    DisableSignup:       false,    // set true to prevent self-registration
    Sessions:            sessionStore, // optional; enables session tracking and refresh tokens
    RefreshTokenTTL:     handler.DefaultRefreshTokenTTL, // defaults to 7 days when Sessions is set
    RefreshCookieName:   "refresh",  // required when Sessions is set; stores refresh token in an HttpOnly cookie
    RequireVerification: true,       // optional; rejects login for unverified email addresses
}
```

!!! note "`AuthHandler.Verifications` field"
    `AuthHandler` declares a `Verifications auth.EmailVerificationStore` field on its struct, but no `AuthHandler` method reads it. Email verification is handled by a separate [`EmailVerificationHandler`](email-verification.md) which has its own `Verifications` field. Setting `AuthHandler.Verifications` has no effect; you can safely omit it.

Password constraints: 8–72 bytes (bcrypt cost 12). A password shorter than 8 bytes returns `{"error": "password must be at least 8 bytes"}`; a password longer than 72 bytes returns `{"error": "password must be at most 72 bytes"}`.

## Routes

```
POST   /auth/signup          → h.Signup         // creates account, returns token + user (+ refresh_token when Sessions set)
POST   /auth/login           → h.Login          // returns token + user (+ refresh_token when Sessions set)
POST   /auth/logout          → h.Logout         // clears cookie; revokes session when Sessions set
POST   /auth/refresh         → h.RefreshToken   // rotate refresh token → new access + refresh token (requires Sessions)
GET    /auth/me              → h.Me             // current user profile (requires auth)
PUT    /auth/me              → h.UpdateProfile  // update display name (requires auth)
POST   /auth/password        → h.ChangePassword // change password (requires auth)
```

## Response types

`Signup`, `Login`, and `RefreshToken` return an `AuthResponse` containing `token`, `refresh_token` (when `Sessions` is set), and `user` (a `UserDTO`). These responses also set `Cache-Control: no-store` and `Pragma: no-cache` to prevent tokens from being stored in browser or proxy caches.

`Me` and `UpdateProfile` return a bare `UserDTO`.

See [handler package](index.md#shared-response-types) for the `UserDTO` and `AuthResponse` shapes.

## Session tracking and refresh token rotation

When `Sessions` is set on `AuthHandler`:

- `Signup` and `Login` create a server-side session, embed the session ID as the JWT `jti` claim, and return a `refresh_token` alongside the short-lived access token.
- `Logout` revokes the current session by parsing the session ID from the access token (even if expired). If deletion returns `auth.ErrNotFound` (session already expired or revoked), the error is silently ignored. Any other deletion error is logged as a warning via `slog.WarnContext` and does not affect the HTTP 200 response.
- `RefreshToken` validates the refresh token, atomically revokes the old session, creates a new session, and returns a fresh access token and a new refresh token (rotation). The consumed token is never reusable.
- `RefreshCookieName` is **required** when `Sessions` is set. The refresh token is returned in both the response body **and** an `HttpOnly` cookie.
- Pass `auth.Config{Sessions: sessionStore}` to `Middleware` so that revoked sessions are rejected on every request.

!!! warning "Sessions requires RefreshCookieName"
    When `Sessions` is set, `RefreshCookieName` must also be non-empty. Unlike `OIDCHandler`, `AuthHandler` does not expose a `Validate()` method; the library catches this misconfiguration when a `Signup`, `Login`, or `RefreshToken` call reaches token issuance and returns HTTP 500 `"server misconfiguration"`. Earlier validation or authentication failures still return their normal 4xx responses. Look for the `slog` message `"issueTokens: Sessions is set but RefreshCookieName is empty — call Validate() at startup"` to diagnose this in production.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `Signup` | 201 Created | Success |
| `Signup` | 400 Bad Request | Missing `name`, `email`, or `password`; password outside 8–72 bytes |
| `Signup` | 403 Forbidden | Signup disabled (`DisableSignup: true`) |
| `Signup` | 409 Conflict | Email already registered |
| `Signup` | 500 Internal Server Error | Password hashing failure, store failure, or token/session issuance failure |
| `Login` | 200 OK | Success |
| `Login` | 400 Bad Request | Missing `email` or `password` |
| `Login` | 401 Unauthorized | Invalid credentials |
| `Login` | 403 Forbidden | Email not verified (when `RequireVerification` is set) |
| `Login` | 500 Internal Server Error | Store failure or token/session issuance failure |
| `Logout` | 200 OK | `{"message": "logged out"}` |
| `RefreshToken` | 200 OK | Success |
| `RefreshToken` | 400 Bad Request | Missing refresh token |
| `RefreshToken` | 401 Unauthorized | Invalid, expired, or revoked refresh token; user not found |
| `RefreshToken` | 404 Not Found | Sessions not enabled (`Sessions` is `nil`) |
| `RefreshToken` | 500 Internal Server Error | Store failure or token/session issuance failure |
| `Me` | 200 OK | `UserDTO` |
| `Me` | 401 Unauthorized | Missing or invalid auth token (middleware) |
| `Me` | 404 Not Found | User not found |
| `Me` | 500 Internal Server Error | Store failure |
| `UpdateProfile` | 200 OK | `UserDTO` |
| `UpdateProfile` | 400 Bad Request | Missing or empty `name` |
| `UpdateProfile` | 401 Unauthorized | Missing or invalid auth token (middleware) |
| `UpdateProfile` | 500 Internal Server Error | Store failure |
| `ChangePassword` | 200 OK | `{"message": "password updated"}` |
| `ChangePassword` | 400 Bad Request | Missing fields; password outside 8–72 bytes; OIDC-only account (no password set) |
| `ChangePassword` | 401 Unauthorized | Wrong current password; missing or invalid auth token (middleware) |
| `ChangePassword` | 404 Not Found | User not found |
| `ChangePassword` | 500 Internal Server Error | Store failure or password hashing failure |
