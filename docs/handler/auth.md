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
    RefreshCookieName:   "refresh",  // optional; stores refresh token in an HttpOnly cookie
    RequireVerification: true,       // optional; rejects login for unverified email addresses
    Verifications:       verificationStore, // required when EmailVerificationHandler is mounted
}
```

Password constraints: 8–72 bytes. Bcrypt cost 12.

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

`Signup`, `Login`, and `RefreshToken` return an `AuthResponse` containing `token`, `refresh_token` (when `Sessions` is set), and `user` (a `UserDTO`).

`Me` and `UpdateProfile` return a bare `UserDTO`.

See [handler package](index.md#shared-response-types) for the `UserDTO` and `AuthResponse` shapes.

## Session tracking and refresh token rotation

When `Sessions` is set on `AuthHandler`:

- `Signup` and `Login` create a server-side session, embed the session ID as the JWT `jti` claim, and return a `refresh_token` alongside the short-lived access token.
- `Logout` revokes the current session by parsing the session ID from the access token (even if expired).
- `RefreshToken` validates the refresh token, atomically revokes the old session, creates a new session, and returns a fresh access token and a new refresh token (rotation). The consumed token is never reusable.
- Setting `RefreshCookieName` causes the refresh token to also be delivered and expected via an HttpOnly cookie, in addition to the response body.
- Pass `auth.Config{Sessions: sessionStore}` to `Middleware` so that revoked sessions are rejected on every request.
