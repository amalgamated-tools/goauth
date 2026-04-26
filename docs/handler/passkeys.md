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
    Users:             userStore,
    Passkeys:          passkeyStore,
    WebAuthn:          wa,          // set to nil to disable passkeys
    JWT:               jwtMgr,
    CookieName:        "session",
    SecureCookies:     true,
    Sessions:          sessionStore, // optional; enables session tracking and refresh tokens
    RefreshCookieName: "refresh",    // required when Sessions is set
    RefreshTokenTTL:   7 * 24 * time.Hour, // defaults to DefaultRefreshTokenTTL when Sessions is set
    URLParamFunc:      chi.URLParam,
}
```

## Routes

```
// Public routes
GET  /auth/passkey/enabled                → h.Enabled
POST /auth/passkey/login/begin            → h.BeginAuthentication
POST /auth/passkey/login/finish           → h.FinishAuthentication   // ?session_id=<id>

// Authenticated routes
POST /auth/passkey/register/begin         → h.BeginRegistration
POST /auth/passkey/register/finish        → h.FinishRegistration      // ?session_id=<id>
GET  /auth/passkey/credentials            → h.ListCredentials
DELETE /auth/passkey/credentials/{id}     → h.DeleteCredential
```

## Registration and authentication flow

Registration and authentication use server-side challenge storage (via `PasskeyStore`) instead of cookies, keeping the flow stateless on the client.

## Response types

`FinishAuthentication` returns HTTP 200 with an `AuthResponse` (`token`, `user`, and `refresh_token` when `Sessions` is set) **and** sets the JWT in an `HttpOnly` session cookie. When `Sessions` is `nil`, only the short-lived access JWT is issued and the `refresh_token` field is absent.

!!! info "Session tracking and refresh tokens"
    Set `Sessions`, `RefreshCookieName`, and optionally `RefreshTokenTTL` on `PasskeyHandler` to enable server-side session revocation and refresh-token rotation for passkey logins. Pass `auth.Config{Sessions: sessionStore}` to `auth.Middleware` so revoked sessions are rejected on subsequent requests.

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
