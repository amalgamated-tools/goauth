# goauth

**goauth** is a router-agnostic Go library that provides complete authentication infrastructure for web applications.

It covers JWT session management, email/password auth, OIDC (SSO) login, WebAuthn passkeys, API key authentication, magic link (passwordless) login, TOTP/MFA, email verification, password reset, RBAC, rate limiting, AES-256-GCM encryption, and SMTP email delivery.

## Packages

| Package | Import path | Purpose |
|---|---|---|
| `auth` | `github.com/amalgamated-tools/goauth/auth` | Core primitives: JWT, middleware, RBAC, TOTP, rate limiting, crypto, store interfaces |
| `handler` | `github.com/amalgamated-tools/goauth/handler` | Ready-to-mount HTTP handlers for every auth flow |
| `smtp` | `github.com/amalgamated-tools/goauth/smtp` | SMTP email delivery with TLS/STARTTLS support |
| `maintenance` | `github.com/amalgamated-tools/goauth/maintenance` | Background cleanup of expired tokens and sessions |

## Installation

```sh
go get github.com/amalgamated-tools/goauth
```

Requires Go 1.26+.

## Quick start

```go
// 1. Implement the store interfaces against your database (see "Store interfaces" below).
var userStore    auth.UserStore     // your implementation
var apiKeyStore  auth.APIKeyStore   // your implementation
var sessionStore auth.SessionStore  // your implementation (optional)

// 2. Create a JWT manager (use a short TTL when refresh tokens are enabled).
jwtMgr, err := auth.NewJWTManager("your-secret-at-least-32-bytes-long", 15*time.Minute, "myapp")

// 3. Wire up handlers.
authHandler := &handler.AuthHandler{
    Users:             userStore,
    JWT:               jwtMgr,
    CookieName:        "session",
    SecureCookies:     true,
    Sessions:          sessionStore,      // enables server-side sessions + refresh tokens
    RefreshTokenTTL:   7 * 24 * time.Hour,
    RefreshCookieName: "refresh",         // optional: deliver refresh token via cookie
}
apiKeyHandler := &handler.APIKeyHandler{
    APIKeys:      apiKeyStore,
    Prefix:       "myapp_",
    URLParamFunc: chi.URLParam, // or any router's param extractor
}
sessionHandler := &handler.SessionHandler{
    Sessions:     sessionStore,
    URLParamFunc: chi.URLParam,
}

// 4. Mount routes (example with chi).
r := chi.NewRouter()
r.Post("/auth/signup",   authHandler.Signup)
r.Post("/auth/login",    authHandler.Login)
r.Post("/auth/logout",   authHandler.Logout)
r.Post("/auth/refresh",  authHandler.RefreshToken)

cfg := auth.Config{CookieName: "session", APIKeyPrefix: "myapp_", Sessions: sessionStore}
r.Group(func(r chi.Router) {
    r.Use(auth.Middleware(jwtMgr, cfg, apiKeyStore))
    r.Get("/auth/me",    authHandler.Me)
    r.Put("/auth/me",    authHandler.UpdateProfile)
    r.Post("/auth/password", authHandler.ChangePassword)

    r.Get("/api-keys",         apiKeyHandler.List)
    r.Post("/api-keys",        apiKeyHandler.Create)
    r.Delete("/api-keys/{id}", apiKeyHandler.Delete)

    r.Get("/sessions",         sessionHandler.List)
    r.Delete("/sessions",      sessionHandler.RevokeAll)
    r.Delete("/sessions/{id}", sessionHandler.Revoke)
})
```
