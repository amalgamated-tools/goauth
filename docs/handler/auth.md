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
    Logger:              slog.Default(), // optional; defaults to slog.Default() when nil
}

if err := h.Validate(); err != nil {
    log.Fatal(err)
}
```

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
    When `Sessions` is set, `RefreshCookieName` must also be non-empty. Call `h.Validate()` at server startup to catch this misconfiguration early, before any user reaches token issuance.

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

## Security: timing-safe login

`Login` performs a bcrypt comparison on every login attempt with non-empty credentials, even when the user is not found or the account has no password (OIDC-only accounts). Requests that fail validation before credentials are checked (e.g. missing email/password fields) return 400 before any bcrypt work. This prevents timing attacks that could enumerate valid email addresses by measuring response latency.

The module-level `dummyLoginBcryptHash` variable is computed once at startup using [`auth.MustGenerateDummyBcryptHash`](../auth/crypto.md). When `FindByEmail` returns `auth.ErrNotFound`, or when `user.PasswordHash` is empty, `Login` calls `bcrypt.CompareHashAndPassword` against the dummy hash before responding 401. The result of that comparison is always discarded.

## Observability

`AuthHandler` emits structured log events via `slog` with the request context for trace correlation. Log events emitted directly by `AuthHandler` methods go through the handler's `Logger` field; when `Logger` is `nil`, `slog.Default()` is used. To route `AuthHandler` log events to a separate destination, set `Logger` to a `*slog.Logger` backed by the desired handler.

!!! note "Token issuance logs bypass `Logger`"
    Events emitted during token issuance (marked † below) originate from the shared `issueTokens` helper, which logs via the package-level `slog.Default()` regardless of the `Logger` field. Configure the process-wide default logger to capture these events.

| Event | Level | `slog` message | Endpoint(s) |
|---|---|---|---|
| Password hashing failure | `ERROR` | `"failed to hash password"` | `Signup`, `ChangePassword` |
| User creation store failure | `ERROR` | `"failed to create user"` | `Signup` |
| User lookup store failure | `ERROR` | `"failed to find user by email"` | `Login` |
| Session revocation failure on logout | `WARN` | `"failed to revoke session on logout"` | `Logout` |
| Refresh token lookup store failure | `ERROR` | `"failed to find session by refresh token"` | `RefreshToken` |
| Old session revocation failure | `ERROR` | `"failed to revoke old session on refresh"` | `RefreshToken` |
| User lookup after token rotation | `ERROR` | `"failed to find user on refresh"` | `RefreshToken` |
| User lookup store failure | `ERROR` | `"failed to get user"` | `Me`, `ChangePassword` |
| Profile update store failure | `ERROR` | `"failed to update profile"` | `UpdateProfile` |
| Password update store failure | `ERROR` | `"failed to update password"` | `ChangePassword` |
| Sessions set without `RefreshCookieName` † | `ERROR` | `"issueTokens: Sessions is set but RefreshCookieName is empty — call Validate() at startup"` | `Signup`, `Login`, `RefreshToken` |
| Refresh token generation failure † | `ERROR` | `"failed to generate refresh token"` | `Signup`, `Login`, `RefreshToken` |
| Session creation store failure † | `ERROR` | `"failed to create session"` | `Signup`, `Login`, `RefreshToken` |
| Access token creation failure † | `ERROR` | `"failed to create token"` | `Signup`, `Login`, `RefreshToken` |

The `WARN`-level logout event does not affect the HTTP 200 response. All other events in the table are followed immediately by an HTTP 500 response.
