# goauth

**goauth** is a router-agnostic Go library that provides complete authentication infrastructure for web applications. It covers JWT session management, email/password auth, OIDC (SSO) login, WebAuthn passkeys, API key authentication, rate limiting, AES-256-GCM encryption, and SMTP email delivery.

## Packages

| Package | Import path | Purpose |
|---|---|---|
| `auth` | `github.com/amalgamated-tools/goauth/auth` | Core primitives: JWT, middleware, rate limiting, crypto, store interfaces |
| `handler` | `github.com/amalgamated-tools/goauth/handler` | Ready-to-mount HTTP handlers for every auth flow |
| `smtp` | `github.com/amalgamated-tools/goauth/smtp` | SMTP email delivery with TLS/STARTTLS support |

## Installation

```sh
go get github.com/amalgamated-tools/goauth
```

Requires Go 1.21+.

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

    r.Get("/sessions",        sessionHandler.List)
    r.Delete("/sessions",     sessionHandler.RevokeAll)
    r.Delete("/sessions/{id}", sessionHandler.Revoke)
})
```

---

## `auth` package

### JWTManager

`JWTManager` signs and validates HS256 JWTs. It also derives an OIDC HMAC sub-key and an AES-256-GCM encryption key from the same secret, so a single secret value covers all cryptographic needs.

```go
jwtMgr, err := auth.NewJWTManager(secret, ttl, issuer)
// secret  – signing secret (empty → random, tokens won't survive restarts)
// ttl     – token lifetime (e.g. 24 * time.Hour)
// issuer  – value used for iss/aud claims (defaults to "goauth")

token, err := jwtMgr.CreateToken(ctx, userID)
claims, err := jwtMgr.ValidateToken(ctx, tokenString)
// claims.UserID contains the subject

encrypter, err := jwtMgr.NewSecretEncrypter() // AES-256-GCM, derived from JWT secret
```

Sentinel errors: `auth.ErrInvalidToken`, `auth.ErrExpiredToken`.

### Middleware

```go
cfg := auth.Config{
    CookieName:   "session",  // HttpOnly cookie name
    APIKeyPrefix: "myapp_",   // set to enable API key auth; omit to disable
    Sessions:     sessionStore, // optional; enables server-side session revocation
}

// Require authenticated user on a route group.
r.Use(auth.Middleware(jwtMgr, cfg, apiKeyStore))

// Require admin on a route group.
r.Use(auth.AdminMiddleware(jwtMgr, userStore, cfg, apiKeyStore))

// Read the resolved user ID anywhere downstream.
userID := auth.UserIDFromContext(r.Context())
```

Tokens are accepted from the `Authorization: Bearer <token>` header or from the configured cookie. API keys are **only** accepted from the `Authorization` header. Admin status is checked via the `UserStore.IsAdmin` method and cached for 5 seconds per user.

When `Sessions` is set the middleware validates the JWT `jti` claim against the store and rejects requests whose session has been revoked or expired server-side. API key requests bypass the session check.

### RateLimiter

Per-IP token-bucket limiter compatible with `net/http` middleware and `http.HandlerFunc` wrapping.

```go
// Simple limiter: 5 requests/second, burst of 10.
rl := auth.NewRateLimiter(5, 10)
r.Use(rl.Middleware)

// Behind a reverse proxy – trust X-Forwarded-For from known CIDRs.
cidrs, err := auth.ParseTrustedProxyCIDRs("10.0.0.0/8,172.16.0.0/12")
rl := auth.NewRateLimiterWithTrustedProxies(5, 10, cidrs)
r.Use(rl.Middleware)

// Wrap a single handler instead of a full middleware chain.
http.HandleFunc("/login", rl.Wrap(myHandler))
```

Stale visitor entries are swept lazily every 5 minutes.

### Crypto utilities

```go
// Hash a high-entropy token (e.g. API key) with SHA-256.
hash := auth.HashHighEntropyToken(token)

// Generate n random bytes as lowercase hex.
hex, err := auth.GenerateRandomHex(20) // 40-char hex string

// Generate a dummy bcrypt hash for timing-safe "user not found" paths.
dummy := auth.MustGenerateDummyBcryptHash("fallback-secret")
```

#### SecretEncrypter (AES-256-GCM)

```go
enc, err := jwtMgr.NewSecretEncrypter()

ciphertext, err := enc.Encrypt("sensitive value")
plaintext, err  := enc.Decrypt(ciphertext)
// Decrypt is a no-op if the value doesn't start with the "enc:v1:" prefix.
```

### Store interfaces

The library defines four interfaces that consuming applications implement against their own database.

#### UserStore

```go
type UserStore interface {
    CreateUser(ctx, name, email, passwordHash string) (*User, error)
    CreateOIDCUser(ctx, name, email, oidcSubject string) (*User, error)
    FindByEmail(ctx, email string) (*User, error)
    FindByID(ctx, id string) (*User, error)
    FindByOIDCSubject(ctx, subject string) (*User, error)
    LinkOIDCSubject(ctx, userID, oidcSubject string) error
    UpdatePassword(ctx, userID, passwordHash string) error
    UpdateName(ctx, userID, name string) (*User, error)
    IsAdmin(ctx, userID string) (bool, error)
    CountUsers(ctx) (int, error)
}
```

Return `database/sql.ErrNoRows` (or wrap it) when a record is not found — handlers check for this sentinel to produce correct HTTP status codes.  
Return `auth.ErrEmailExists` from `CreateUser` when a duplicate email is detected.

#### APIKeyStore

```go
type APIKeyStore interface {
    CreateAPIKey(ctx, userID, name, keyHash, keyPrefix string) (*APIKey, error)
    ListAPIKeysByUser(ctx, userID string) ([]APIKey, error)
    FindAPIKeyByIDAndUser(ctx, id, userID string) (*APIKey, error)
    ValidateAPIKey(ctx, keyHash string) (userID, apiKeyID string, err error)
    TouchAPIKeyLastUsed(ctx, id string) error
    DeleteAPIKey(ctx, id, userID string) error
}
```

`ValidateAPIKey` is given the SHA-256 hex hash of the raw key. Store only the hash — never the plaintext key.

#### SessionStore

```go
type SessionStore interface {
    CreateSession(ctx, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*Session, error)
    FindSessionByID(ctx, id string) (*Session, error)
    FindSessionByRefreshTokenHash(ctx, hash string) (*Session, error)
    ListSessionsByUser(ctx, userID string) ([]Session, error)
    DeleteSession(ctx, id, userID string) error
    DeleteAllSessionsByUser(ctx, userID string) error
    DeleteExpiredSessions(ctx) error
}
```

Each session is bound to one refresh token hash. Only the SHA-256 hash of the refresh token is persisted.  
Return `database/sql.ErrNoRows` from `FindSessionByID`, `FindSessionByRefreshTokenHash`, and `DeleteSession` when the record is not found.

#### PasskeyStore

```go
type PasskeyStore interface {
    CreateChallenge(ctx, userID *string, sessionData string, expiresAt time.Time) (*PasskeyChallenge, error)
    GetAndDeleteChallenge(ctx, id string) (*PasskeyChallenge, error)
    DeleteExpiredChallenges(ctx) error
    CreateCredential(ctx, userID, name, credentialID, credentialData, aaguid string) (*PasskeyCredential, error)
    ListCredentialsByUser(ctx, userID string) ([]PasskeyCredential, error)
    FindCredentialByCredentialID(ctx, credentialID string) (*PasskeyCredential, error)
    FindCredentialByIDAndUser(ctx, id, userID string) (*PasskeyCredential, error)
    UpdateCredentialData(ctx, userID, credentialID, credentialData string) error
    DeleteCredential(ctx, id, userID string) error
}
```

`userID` in `CreateChallenge` is `nil` during authentication (discoverable login) and non-nil during registration.

---

## `handler` package

All handlers use `net/http` only and are compatible with any router. Router-specific helpers (e.g. URL parameter extraction) are injected via a `func(r *http.Request, key string) string` field.

### AuthHandler – email/password

```go
h := &handler.AuthHandler{
    Users:             userStore,
    JWT:               jwtMgr,
    CookieName:        "session",
    SecureCookies:     true,
    DisableSignup:     false,    // set true to prevent self-registration
    Sessions:          sessionStore, // optional; enables session tracking and refresh tokens
    RefreshTokenTTL:   7 * 24 * time.Hour, // defaults to 7 days when Sessions is set
    RefreshCookieName: "refresh",  // optional; stores refresh token in an HttpOnly cookie
}

// Routes
POST   /auth/signup          → h.Signup         // creates account, returns token + user (+ refresh_token when Sessions set)
POST   /auth/login           → h.Login          // returns token + user (+ refresh_token when Sessions set)
POST   /auth/logout          → h.Logout         // clears cookie; revokes session when Sessions set
POST   /auth/refresh         → h.RefreshToken   // rotate refresh token → new access + refresh token (requires Sessions)
GET    /auth/me              → h.Me             // current user profile (requires auth)
PUT    /auth/me              → h.UpdateProfile  // update display name (requires auth)
POST   /auth/password        → h.ChangePassword // change password (requires auth)
```

Password constraints: 8–72 bytes. Bcrypt cost 12.

#### Session tracking and refresh token rotation

When `Sessions` is set on `AuthHandler`:

- `Signup` and `Login` create a server-side session, embed the session ID as the JWT `jti` claim, and return a `refresh_token` alongside the short-lived access token.
- `Logout` revokes the current session by parsing the session ID from the access token (even if expired).
- `RefreshToken` validates the refresh token, atomically revokes the old session, creates a new session, and returns a fresh access token and a new refresh token (rotation). The consumed token is never reusable.
- Setting `RefreshCookieName` causes the refresh token to also be delivered and expected via an HttpOnly cookie, in addition to the response body.
- Pass `auth.Config{Sessions: sessionStore}` to `Middleware` so that revoked sessions are rejected on every request.

### OIDCHandler – SSO / OpenID Connect

```go
h, err := handler.NewOIDCHandler(
    ctx,
    userStore, jwtMgr,
    "https://accounts.google.com", // OIDC issuer URL (discovery performed at startup)
    clientID, clientSecret,
    "https://myapp.example.com/auth/oidc/callback",
    "session", true,
)

// Routes
GET  /auth/oidc/login                  → h.Login              // redirects to provider
GET  /auth/oidc/callback               → h.Callback           // handles provider redirect
POST /auth/oidc/link-nonce             → h.CreateLinkNonce    // issue nonce for linking (requires auth)
GET  /auth/oidc/link?nonce=<nonce>     → h.Link               // start link flow (requires auth)
```

The callback performs PKCE verification and handles three cases automatically: existing OIDC subject → log in; existing email → link subject and log in; new user → create account.  
Account linking uses a short-lived (5-minute) HMAC-signed state token so the user's browser never sees the user ID in plaintext.

### APIKeyHandler

```go
h := &handler.APIKeyHandler{
    APIKeys:      apiKeyStore,
    Prefix:       "myapp_",   // prepended to the random hex token
    URLParamFunc: chi.URLParam,
}

// Routes (all require auth middleware)
GET    /api-keys        → h.List    // list keys (prefix + metadata only, never the raw key)
POST   /api-keys        → h.Create  // create key; raw key returned once, never again
DELETE /api-keys/{id}   → h.Delete
```

Keys are 160-bit random values prefixed with the configured string. Only the SHA-256 hash is persisted. The raw key is returned in the `key` field of the creation response only.

### SessionHandler – session listing and revocation

```go
h := &handler.SessionHandler{
    Sessions:     sessionStore,
    URLParamFunc: chi.URLParam,
}

// Routes (all require auth middleware)
GET    /sessions        → h.List       // list active sessions for the current user
DELETE /sessions/{id}   → h.Revoke     // revoke a specific session (204 No Content)
DELETE /sessions        → h.RevokeAll  // revoke all sessions for the current user (204 No Content)
```

Each `SessionDTO` in the list response contains `id`, `user_agent`, `ip_address`, `expires_at`, and `created_at`. The `id` can be passed to `Revoke` to force a remote sign-out.

### PasskeyHandler – WebAuthn

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

Registration and authentication use server-side challenge storage (via `PasskeyStore`) instead of cookies, keeping the flow stateless on the client. Discoverable login is used so users do not need to enter an identifier before presenting a passkey.

### Cookie helpers

```go
handler.SetAuthCookie(w, token, cookieName, secure)   // HttpOnly, SameSite=Strict
handler.ClearAuthCookie(w, cookieName, secure)
```

---

## `smtp` package

```go
cfg := smtp.LoadConfig() // reads SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, SMTP_TLS

if cfg.Enabled() {
    params, err := cfg.Validate()
    // ...
    err = smtp.Send(ctx, params, "recipient@example.com", rawMIMEMessage)
}
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | *(required)* | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | | Auth username (omit for unauthenticated) |
| `SMTP_PASSWORD` | | Auth password |
| `SMTP_FROM` | *(required)* | Sender address, RFC 5322 format (`Name <addr>` or bare address) |
| `SMTP_TLS` | `starttls` | TLS mode: `none`, `starttls`, or `tls` |

`smtp.Send` accepts a raw RFC 2822/MIME message as `[]byte`. Composing message bodies and templates is left to the consuming application.

---

## Security notes

- **Secrets** – Pass a secret of at least `auth.MinSecretLength` (32) bytes to `NewJWTManager`. A shorter secret is accepted but not recommended.
- **API keys** – Only the SHA-256 hash of each key is stored. The plaintext key cannot be recovered after the creation response.
- **Timing attacks** – `AuthHandler.Login` always runs a bcrypt comparison even when the user is not found, preventing username enumeration via timing.
- **OIDC PKCE** – The OIDC flow uses S256 PKCE and validates the state parameter on every callback.
- **Rate limiting** – Apply `RateLimiter.Middleware` to login, signup, and passkey endpoints to limit brute-force attempts.
- **Cookie security** – Set `SecureCookies: true` in production. Auth cookies use `HttpOnly` and `SameSite=Strict`.
- **Trusted proxies** – If your application runs behind a load balancer, use `NewRateLimiterWithTrustedProxies` and restrict the trusted CIDR list to your actual proxy addresses.
- **Session revocation** – When `Sessions` is configured, short-lived access tokens (e.g. 15 minutes) are paired with long-lived refresh tokens. Revoking a session (via `SessionHandler.Revoke` or `Logout`) instantly invalidates the bound access token on the next request when the middleware is configured with the same `SessionStore`.
- **Refresh token rotation** – Each `RefreshToken` call atomically replaces the refresh token. The old token is consumed and cannot be reused, limiting the impact of token theft.
