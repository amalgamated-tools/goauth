# PasskeyHandler — WebAuthn Passkeys

`PasskeyHandler` provides WebAuthn passkey registration and authentication using discoverable credentials (users do not need to enter an identifier before presenting a passkey).

## Configuration

```go
wa, err := webauthn.New(&webauthn.Config{
    RPDisplayName: "My App",
    RPID:          "myapp.example.com",
    RPOrigins:     []string{"https://myapp.example.com"},
})

h := &handler.PasskeyHandler{
    Users:         userStore,
    Passkeys:      passkeyStore,
    WebAuthn:      wa,         // set to nil to disable passkeys
    JWT:           jwtMgr,
    CookieName:    "session",
    SecureCookies: true,
    URLParamFunc:  chi.URLParam,
    // Optional: enable session tracking and refresh-token rotation.
    Sessions:          sessionStore,
    RefreshTokenTTL:   handler.DefaultRefreshTokenTTL, // default 7 days
    RefreshCookieName: "refresh",
}
```

## Routes

```
// Public routes
GET  /auth/passkey/enabled                → h.Enabled               // {"enabled": <bool>}
POST /auth/passkey/login/begin            → h.BeginAuthentication   // → {session_id, options}
POST /auth/passkey/login/finish           → h.FinishAuthentication  // ?session_id=<id>

// Authenticated routes
POST /auth/passkey/register/begin         → h.BeginRegistration     // body: {"name": "..."} (max 100 chars) → {session_id, options}
POST /auth/passkey/register/finish        → h.FinishRegistration    // ?session_id=<id>  (201 Created)
GET  /auth/passkey/credentials            → h.ListCredentials
DELETE /auth/passkey/credentials/{id}     → h.DeleteCredential      // 204 No Content
```

## Registration and authentication flow

Registration and authentication use server-side challenge storage (via `PasskeyStore`) instead of cookies, keeping the flow stateless on the client. Challenges expire after **5 minutes**; presenting a `session_id` whose challenge has expired returns HTTP 400 or 401.

**Registration:**

1. `BeginRegistration` — authenticated user sends `{"name": "My Phone"}`. The handler returns a `session_id` and an `options` object (WebAuthn `PublicKeyCredentialCreationOptions`) to pass to `navigator.credentials.create()`.
2. `FinishRegistration` — client submits the created credential with `?session_id=<id>` from step 1.

**Authentication:**

1. `BeginAuthentication` — returns a `session_id` and an `options` object (WebAuthn `PublicKeyCredentialRequestOptions`) to pass to `navigator.credentials.get()`.
2. `FinishAuthentication` — client submits the assertion with `?session_id=<id>` from step 1.

## Response types

`FinishAuthentication` returns HTTP 200 with an `AuthResponse` (`token`, `refresh_token` when `Sessions` is set, and `user`) **and** sets the JWT in an `HttpOnly` session cookie. When `Sessions` is set, a refresh token cookie is also set via `RefreshCookieName` (which is required when `Sessions` is set). The response also sets `Cache-Control: no-store` and `Pragma: no-cache` to prevent tokens from being stored in browser or proxy caches.

When `Sessions` is `nil`, `PasskeyHandler` issues an access JWT only. The token lifetime is determined by the configured `JWTManager`.

## Session tracking and refresh tokens

When `Sessions` is set on `PasskeyHandler`:

- `FinishAuthentication` creates a server-side session, embeds the session ID as the JWT `jti` claim, and returns a `refresh_token` alongside the short-lived access token.
- `RefreshCookieName` is **required** when `Sessions` is set. The refresh token is returned in both the response body **and** an `HttpOnly` cookie.
- Pass `auth.Config{CookieName: "session", Sessions: sessionStore}` to `Middleware` so that revoked sessions are rejected on every request.

Session tracking and refresh token rotation work identically to `AuthHandler`. Refresh token rotation (via `AuthHandler.RefreshToken`) requires `AuthHandler` to be mounted — `PasskeyHandler` does not expose a dedicated refresh endpoint.

!!! note "Credential counter updates"
    After a successful authentication, `FinishAuthentication` updates the stored credential data (including the WebAuthn signature counter) via `PasskeyStore.UpdateCredentialData`. A failure to persist the counter is logged as a warning but **does not fail** the authentication. The counter is used to detect cloned authenticators — if the counter from the device is less than or equal to the stored value, the WebAuthn library flags it as a potential clone.

`FinishRegistration` returns a single `PasskeyCredentialDTO` (HTTP 201); `ListCredentials` returns `[]PasskeyCredentialDTO` (HTTP 200):

```go
type PasskeyCredentialDTO struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    AAGUID    string    `json:"aaguid"`
    CreatedAt time.Time `json:"created_at"`
}
```

The `id` field can be passed to `DeleteCredential` to remove a specific passkey.

## Disabling passkeys

Set `WebAuthn: nil` to deploy `PasskeyHandler` in a disabled state. `Enabled` returns `{"enabled": false}` normally. All other endpoints (`BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, `FinishAuthentication`) return HTTP 503 "passkeys not configured". `ListCredentials` and `DeleteCredential` remain accessible via auth middleware but are not affected by the `WebAuthn` field.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `Enabled` | 200 OK | Always |
| `BeginRegistration` | 200 OK | `{session_id, options}` |
| `BeginRegistration` | 400 Bad Request | Missing or empty `name`; `name` exceeds 100 characters |
| `BeginRegistration` | 404 Not Found | User not found |
| `BeginRegistration` | 503 Service Unavailable | `WebAuthn` is `nil` (passkeys disabled) |
| `BeginRegistration` | 500 Internal Server Error | Store error fetching user; failed to list credentials, begin WebAuthn ceremony, or store challenge |
| `FinishRegistration` | 201 Created | `PasskeyCredentialDTO` |
| `FinishRegistration` | 400 Bad Request | Missing `session_id`; invalid/expired session; registration verification failed |
| `FinishRegistration` | 503 Service Unavailable | `WebAuthn` is `nil` |
| `FinishRegistration` | 500 Internal Server Error | Failed to fetch user, list credentials, marshal credential, or store credential |
| `BeginAuthentication` | 200 OK | `{session_id, options}` |
| `BeginAuthentication` | 503 Service Unavailable | `WebAuthn` is `nil` |
| `BeginAuthentication` | 500 Internal Server Error | Failed to begin WebAuthn ceremony or store challenge |
| `FinishAuthentication` | 200 OK | `AuthResponse` |
| `FinishAuthentication` | 400 Bad Request | Missing `session_id` |
| `FinishAuthentication` | 401 Unauthorized | Invalid/expired session; WebAuthn verification failed |
| `FinishAuthentication` | 503 Service Unavailable | `WebAuthn` is `nil` |
| `FinishAuthentication` | 500 Internal Server Error | Store failure during authentication |
| `ListCredentials` | 200 OK | `[]PasskeyCredentialDTO` |
| `ListCredentials` | 500 Internal Server Error | Store failure |
| `DeleteCredential` | 204 No Content | Success |
| `DeleteCredential` | 400 Bad Request | Missing credential ID |
| `DeleteCredential` | 404 Not Found | Credential not found or not owned by the authenticated user |
| `DeleteCredential` | 500 Internal Server Error | Store failure |
