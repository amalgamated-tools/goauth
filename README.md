# goauth

**goauth** is a router-agnostic Go library that provides complete authentication infrastructure for web applications. It covers JWT session management, email/password auth, OIDC (SSO) login, WebAuthn passkeys, API key authentication, rate limiting, AES-256-GCM encryption, and SMTP email delivery.

## Packages

| Package | Import path | Purpose |
|---|---|---|
| `auth` | `github.com/amalgamated-tools/goauth/auth` | Core primitives: JWT, middleware, rate limiting, RBAC, crypto, store interfaces |
| `handler` | `github.com/amalgamated-tools/goauth/handler` | Ready-to-mount HTTP handlers for every auth flow |
| `smtp` | `github.com/amalgamated-tools/goauth/smtp` | SMTP email delivery with TLS/STARTTLS support |
| `maintenance` | `github.com/amalgamated-tools/goauth/maintenance` | Background goroutine for periodic cleanup of expired tokens and sessions |

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

### Sentinel errors reference

| Error | When returned |
|---|---|
| `auth.ErrInvalidToken` | Token signature or structure is invalid |
| `auth.ErrExpiredToken` | Token has passed its `exp` claim |
| `auth.ErrEmailExists` | `CreateUser` called with an already-registered email |
| `auth.ErrEmailNotVerified` | A flow requires a verified email but the account's `EmailVerified` is false |
| `auth.ErrSessionRevoked` | Middleware finds the JWT `jti` in the store but the session is revoked |
| `auth.ErrNotFound` | Store method found no matching record |
| `auth.ErrTOTPNotFound` | `GetTOTPSecret` called for a user who has not enrolled TOTP |
| `auth.ErrInvalidTOTPCode` | TOTP code verification failed |
| `auth.ErrOIDCSubjectAlreadyLinked` | `LinkOIDCSubject` called when the subject is already linked to the user (benign no-op) |

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

### RBAC (role-based access control)

goauth ships a lightweight RBAC layer built on top of `RBACUserStore`. Three built-in roles are pre-configured with default permissions; applications can override or extend them.

**Built-in roles and permissions**

| Role | Permissions |
|---|---|
| `auth.RoleAdmin` | `manage_users`, `read_content`, `write_content` |
| `auth.RoleEditor` | `read_content`, `write_content` |
| `auth.RoleViewer` | `read_content` |

```go
// Extend or override role permissions at startup.
auth.RegisterRolePermissions(auth.RoleAdmin, []auth.Permission{
    auth.PermManageUsers,
    auth.PermReadContent,
    auth.PermWriteContent,
    "billing:read", // custom permission
})

// Build a checker backed by your store.
checker := auth.NewStoreRoleChecker(rbacStore) // rbacStore implements auth.RBACUserStore

// Wrap with an in-process cache (recommended for hot paths).
cached := auth.NewCachingRoleChecker(checker, 30*time.Second)

// Use in handlers.
ok, err := cached.HasRole(ctx, userID, auth.RoleAdmin)
ok, err  = cached.HasPermission(ctx, userID, auth.PermWriteContent)
```

**`RBACUserStore` interface**

```go
type RBACUserStore interface {
    GetRoles(ctx, userID string) ([]Role, error)
    AssignRole(ctx, userID string, role Role) error
    RevokeRole(ctx, userID string, role Role) error
}
```

`RBACUserStore` is independent of `UserStore`; implement it only when you want role-based access control.

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

// Generate n random bytes as a URL-safe base64 string (no padding).
b64, err := auth.GenerateRandomBase64(32) // used internally for magic links / reset tokens

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

Return `auth.ErrNotFound` (or wrap it) when a record is not found — handlers check for this sentinel to produce correct HTTP status codes.  
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
Return `auth.ErrNotFound` from `FindSessionByID`, `FindSessionByRefreshTokenHash`, and `DeleteSession` when the record is not found.

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

#### MagicLinkStore

```go
type MagicLinkStore interface {
    CreateMagicLink(ctx, email, tokenHash string, expiresAt time.Time) (*MagicLink, error)
    // FindAndDeleteMagicLink atomically retrieves and removes the record.
    // Returns ErrNotFound when not found.
    FindAndDeleteMagicLink(ctx, tokenHash string) (*MagicLink, error)
    DeleteExpiredMagicLinks(ctx) error
}
```

Only the SHA-256 hash of the raw token is persisted. `FindAndDeleteMagicLink` must be atomic (SELECT + DELETE in one transaction) to prevent replay.

#### EmailVerificationStore

```go
type EmailVerificationStore interface {
    CreateEmailVerification(ctx, userID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error)
    // ConsumeEmailVerification looks up the token by hash, deletes it, and returns it.
    // Returns ErrNotFound when not found.
    ConsumeEmailVerification(ctx, tokenHash string) (*EmailVerificationToken, error)
    SetEmailVerified(ctx, userID string) error
}
```

#### TOTPStore

```go
type TOTPStore interface {
    // CreateTOTPSecret replaces any existing secret for the user.
    CreateTOTPSecret(ctx, userID, secret string) (*TOTPSecret, error)
    // GetTOTPSecret returns ErrTOTPNotFound when none exists.
    GetTOTPSecret(ctx, userID string) (*TOTPSecret, error)
    DeleteTOTPSecret(ctx, userID string) error
}
```

The `Secret` field is the unpadded base32-encoded TOTP secret. Applications may encrypt it at rest before storing.

#### PasswordResetStore

```go
type PasswordResetStore interface {
    CreatePasswordResetToken(ctx, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
    // FindPasswordResetToken returns ErrInvalidToken when not found.
    FindPasswordResetToken(ctx, tokenHash string) (*PasswordResetToken, error)
    DeletePasswordResetToken(ctx, id string) error
    DeleteExpiredPasswordResetTokens(ctx) error
}
```

Only the SHA-256 hash of the raw token is stored. Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation.

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

### MagicLinkHandler – passwordless email login

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
    RefreshCookieName: "refresh",         // optional
}

// Routes
POST /auth/magic-link/request  → h.RequestMagicLink  // always 200; sends token to email if address is known
GET  /auth/magic-link/verify   → h.VerifyMagicLink   // ?token=<raw-token>; issues JWT + optional refresh token
```

- Tokens expire after **15 minutes** and are one-time use (atomically deleted on redemption).
- If the email address is not registered, `VerifyMagicLink` auto-provisions a passwordless account (empty `PasswordHash`).
- `RequestMagicLink` always returns 200 to avoid leaking whether an address is registered.

### EmailVerificationHandler

```go
h := &handler.EmailVerificationHandler{
    Users:         userStore,
    Verifications: emailVerificationStore,
    SendEmail:     func(ctx context.Context, to, token string) error { /* send email */ return nil },
    TokenTTL:      24 * time.Hour, // defaults to 24 h
}

// Routes
POST /verify-email/send  → h.SendVerification  // always 200; sends token if address is registered and unverified
GET  /verify-email       → h.VerifyEmail       // ?token=<plaintext-token>; marks email as verified
```

- Tokens expire after `TokenTTL` (default 24 hours).
- `SendVerification` always returns 200 to avoid leaking account existence.
- `VerifyEmail` returns 400 on invalid/expired tokens and 200 on success.

### PasswordResetHandler

```go
h := &handler.PasswordResetHandler{
    Users:          userStore,
    Resets:         passwordResetStore,
    SendResetEmail: func(ctx context.Context, toEmail, rawToken string) error { /* send email */ return nil },
    TokenTTL:       time.Hour, // defaults to 1 h
    RateLimiter:    rl,        // optional; recommended on the request endpoint
}

// Routes
POST /password-reset/request  → h.RequestReset    // always 200; sends token if email is registered
POST /password-reset/confirm  → h.ResetPassword   // {"token":"…","newPassword":"…"}
```

- Only accounts with a non-empty `PasswordHash` can use this flow (OIDC-only accounts are silently skipped).
- `RequestReset` applies `RateLimiter` (if set) before processing.
- Tokens are consumed (deleted) on successful use. If email delivery fails, the orphaned token is cleaned up automatically.

### TOTPHandler – TOTP / MFA

```go
h := &handler.TOTPHandler{
    TOTP:      totpStore,
    Users:     userStore,
    Issuer:    "MyApp",
    UsedCodes: auth.TOTPUsedCodeCache{}, // zero value is ready; embed in a long-lived struct
}

// All routes require auth middleware.
POST   /totp/generate  → h.Generate  // generate secret + provisioning URI (not yet saved)
POST   /totp/enroll    → h.Enroll    // {"secret":"…","code":"…"}; verifies code, then saves secret
POST   /totp/verify    → h.Verify    // {"code":"…"}; validates against enrolled secret
GET    /totp/status    → h.Status    // {"enrolled":true|false}
DELETE /totp           → h.Disable   // removes enrolled secret (204 No Content)
```

**Enrollment flow:**

1. `POST /totp/generate` — server returns `secret` (base32) and `provisioning_uri` (otpauth://). Display the URI as a QR code.
2. User scans QR code with their authenticator app.
3. `POST /totp/enroll` — client sends the same `secret` plus the first 6-digit `code`. On success the secret is persisted.

`TOTPUsedCodeCache` (zero value ready) prevents replay attacks within the ~90-second validity window. It is safe for concurrent use. For multi-instance deployments, supplement with a shared distributed cache keyed by `userID + "\x00" + code`.

### Cookie helpers

```go
handler.SetAuthCookie(w, token, cookieName, secure)   // HttpOnly, SameSite=Strict
handler.ClearAuthCookie(w, cookieName, secure)
```

---

## `maintenance` package

`maintenance.StartCleanup` runs a set of cleanup functions in a background goroutine, immediately on start and then on every interval. Use it to periodically purge expired tokens, sessions, and challenges so your database stays bounded in size.

```go
import "github.com/amalgamated-tools/goauth/maintenance"

stop := maintenance.StartCleanup(ctx, 10*time.Minute,
    sessionStore.DeleteExpiredSessions,
    magicLinkStore.DeleteExpiredMagicLinks,
    passkeyStore.DeleteExpiredChallenges,
    passwordResetStore.DeleteExpiredPasswordResetTokens,
)
defer stop() // blocks until the goroutine exits
```

- Each cleaner runs once immediately when `StartCleanup` is called, then once per `interval`.
- Panics inside a cleaner are recovered and logged via `slog`; they do not stop other cleaners.
- `stop()` cancels the goroutine and blocks until it exits — always defer it to avoid goroutine leaks.
- `interval` must be positive; `StartCleanup` panics otherwise.

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
- **TOTP replay protection** – `TOTPUsedCodeCache` prevents a valid 6-digit code from being accepted twice within the ~90-second validity window. For multi-instance deployments, supplement with a shared external cache.
- **Magic links / reset tokens** – Raw tokens are never stored; only their SHA-256 hash is persisted. Tokens are one-time use and short-lived (15 min for magic links, 1 h for password resets by default).
- **Email enumeration** – `RequestMagicLink`, `SendVerification`, and `RequestReset` always return HTTP 200, regardless of whether the email is registered, to prevent account enumeration.
