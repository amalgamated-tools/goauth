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

`FinishAuthentication` returns HTTP 200 with an `AuthResponse` (`token` + `user`) **and** sets the JWT in an `HttpOnly` session cookie. There is no `refresh_token` field — `PasskeyHandler` always issues a plain short-lived JWT.

!!! info "Adding session tracking"
    To enable server-side sessions and refresh-token rotation for passkey logins, create a session and re-issue the JWT manually after `FinishAuthentication` succeeds using `JWTManager.CreateTokenWithSession`.

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
