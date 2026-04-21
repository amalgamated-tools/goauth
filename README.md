# goauth

**goauth** is a router-agnostic Go library that provides complete authentication infrastructure for web applications. It covers JWT session management, email/password auth, OIDC (SSO) login, WebAuthn passkeys, API key authentication, magic link (passwordless) login, TOTP/MFA, email verification, password reset, RBAC, rate limiting, AES-256-GCM encryption, and SMTP email delivery.

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
// CreateTokenWithSession embeds the session ID as the JWT jti claim.
// Use this (or let AuthHandler do it automatically) when Sessions is enabled.
token, err := jwtMgr.CreateTokenWithSession(ctx, userID, sessionID)

claims, err := jwtMgr.ValidateToken(ctx, tokenString)
// claims.UserID contains the subject; claims.ID contains the session ID (jti)

// ParseTokenClaims validates the signature (and iss/aud) but ignores all
// time-based claim validation (expiry, not-before, issued-at).
// Useful for logout or audit flows that need the session ID from a token
// that may be expired, not yet valid, or otherwise outside time-based checks.
claims, err := jwtMgr.ParseTokenClaims(tokenString)

encrypter, err := jwtMgr.NewSecretEncrypter() // AES-256-GCM, derived from JWT secret

// HMACSign/HMACVerify use an OIDC-derived sub-key for creating and verifying
// HMAC-SHA256 signatures. Useful for custom flows that need a MAC tied to the
// JWT secret (e.g. signed redirect state) without exposing the raw secret.
data := []byte("example payload")
sig := jwtMgr.HMACSign(data)
ok := jwtMgr.HMACVerify(data, sig)
```

Sentinel errors: `auth.ErrInvalidToken`, `auth.ErrExpiredToken`, `auth.ErrNotFound`, `auth.ErrEmailExists`, `auth.ErrEmailNotVerified`, `auth.ErrSessionRevoked`, `auth.ErrTOTPNotFound`, `auth.ErrInvalidTOTPCode`, `auth.ErrOIDCSubjectAlreadyLinked`.

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
// The second argument is an auth.AdminChecker; UserStore satisfies this interface.
r.Use(auth.AdminMiddleware(jwtMgr, userStore, cfg, apiKeyStore))

// Require a specific role or permission on a route group (see RBAC below).
r.Use(auth.RequireRole(jwtMgr, roleChecker, cfg, apiKeyStore, auth.RoleEditor))
r.Use(auth.RequirePermission(jwtMgr, roleChecker, cfg, apiKeyStore, auth.PermWriteContent))

// Read the resolved user ID anywhere downstream.
userID := auth.UserIDFromContext(r.Context())

// ContextWithUserID injects a user ID into a context manually.
// Useful in tests or custom middleware that bypass the standard auth flow.
ctx := auth.ContextWithUserID(r.Context(), userID)

// Store/retrieve arbitrary roles in context for downstream handlers.
ctx = auth.ContextWithRoles(ctx, []auth.Role{auth.RoleAdmin})
roles := auth.RolesFromContext(ctx)
```

Tokens are accepted from the `Authorization: Bearer <token>` header or from the configured cookie. API keys are **only** accepted from the `Authorization` header. Admin status is checked via the `AdminChecker.IsAdmin` method and cached for 5 seconds per user.

When `Sessions` is set the middleware validates the JWT `jti` claim against the store and rejects requests whose session has been revoked or expired server-side. API key requests bypass the session check.

### RBAC (role-based access control)

goauth ships a lightweight RBAC layer built on top of `RBACUserStore`. Three built-in roles are pre-configured with default permissions; applications can override or extend them.

**Built-in roles and permissions**

| Role | Permissions |
|---|---|
| `auth.RoleAdmin` | `auth.PermManageUsers`, `auth.PermReadContent`, `auth.PermWriteContent` |
| `auth.RoleEditor` | `auth.PermReadContent`, `auth.PermWriteContent` |
| `auth.RoleViewer` | `auth.PermReadContent` |

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
ok, err = cached.HasPermission(ctx, userID, auth.PermWriteContent)

// Adapt a RoleChecker to satisfy AdminChecker (for use with AdminMiddleware).
adminChecker := auth.NewAdminCheckerFromRoleChecker(cached)
```

See [`RBACUserStore`](#rbacuserstore) in the Store interfaces section below.

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

// Programmatic check (returns bool, does not write an HTTP response).
if !rl.Allow(r) {
    http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
    return
}
```

Stale visitor entries are swept lazily every 5 minutes.

### Crypto utilities

```go
// Hash a high-entropy token (e.g. API key) with SHA-256.
tokenHash := auth.HashHighEntropyToken(token)

// Generate n random bytes as lowercase hex.
hex, err := auth.GenerateRandomHex(20) // 40-char hex string

// Generate n random bytes as URL-safe base64.
b64, err := auth.GenerateRandomBase64(32) // 43-char base64url string

// Generate a dummy bcrypt hash for timing-safe "user not found" paths.
dummy := auth.MustGenerateDummyBcryptHash("fallback-secret")

// BcryptCost is the work factor used throughout the library (cost 12).
// Use it when hashing passwords in your own code to stay consistent.
passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
```

#### SecretEncrypter (AES-256-GCM)

```go
enc, err := jwtMgr.NewSecretEncrypter()

ciphertext, err := enc.Encrypt("sensitive value")
plaintext, err  := enc.Decrypt(ciphertext)
// Decrypt is a no-op if the value doesn't start with the "enc:v1:" prefix.
```

### Store interfaces

The library defines store interfaces that consuming applications implement against their own database.

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

The `User` struct returned by store methods has the following fields:

```go
type User struct {
    ID            string
    Name          string
    Email         string
    PasswordHash  string  // empty for OIDC-only accounts (no password set)
    OIDCSubject   *string // nil when no OIDC identity is linked
    IsAdmin       bool
    EmailVerified bool
    CreatedAt     time.Time
}
```

Accounts with an empty `PasswordHash` cannot authenticate or reset passwords through password-based flows; they are treated as OIDC-only.

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
    FindAndDeleteMagicLink(ctx, tokenHash string) (*MagicLink, error)
    DeleteExpiredMagicLinks(ctx) error
}
```

`FindAndDeleteMagicLink` atomically retrieves and removes the record matching `tokenHash`. Returns `auth.ErrNotFound` when not found. Only the SHA-256 hash of the raw token is persisted.

#### EmailVerificationStore

```go
type EmailVerificationStore interface {
    CreateEmailVerification(ctx, userID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error)
    ConsumeEmailVerification(ctx, tokenHash string) (*EmailVerificationToken, error)
    SetEmailVerified(ctx, userID string) error
}
```

`ConsumeEmailVerification` atomically looks up and deletes the token. Returns `auth.ErrNotFound` when not found.

#### TOTPStore

```go
type TOTPStore interface {
    CreateTOTPSecret(ctx, userID, secret string) (*TOTPSecret, error)
    GetTOTPSecret(ctx, userID string) (*TOTPSecret, error)
    DeleteTOTPSecret(ctx, userID string) error
}
```

`GetTOTPSecret` returns `auth.ErrTOTPNotFound` when no secret is enrolled for the user. `CreateTOTPSecret` replaces any existing secret. The `Secret` field holds the unpadded base32-encoded TOTP secret.

#### PasswordResetStore

```go
type PasswordResetStore interface {
    CreatePasswordResetToken(ctx, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
    FindPasswordResetToken(ctx, tokenHash string) (*PasswordResetToken, error)
    DeletePasswordResetToken(ctx, id string) error
    DeleteExpiredPasswordResetTokens(ctx) error
}
```

`FindPasswordResetToken` returns `auth.ErrInvalidToken` when no matching record exists. Only the SHA-256 hash of the raw token is stored. Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation.

#### RBACUserStore

```go
type RBACUserStore interface {
    GetRoles(ctx context.Context, userID string) ([]Role, error)
    AssignRole(ctx context.Context, userID string, role Role) error
    RevokeRole(ctx context.Context, userID string, role Role) error
}
```

Implement this interface to enable role-based access control. It is separate from `UserStore` and only required when you use `RequireRole` or `RequirePermission` middleware.

### TOTP / MFA

```go
// During enrollment – generate a secret and return a QR code URI.
secret, err := auth.GenerateTOTPSecret()
uri := auth.TOTPProvisioningURI(secret, user.Email, "MyApp")

// During verification – validate a 6-digit code.
// Uses a ±1 time-step window to tolerate clock skew (~30 s).
ok, err := auth.ValidateTOTP(secret, code)

// GenerateTOTPCode computes the expected code for a given time.
// Intended for testing and tooling; use ValidateTOTP in production.
generatedCode, err := auth.GenerateTOTPCode(secret, time.Now())
```

**Replay protection** – `ValidateTOTP` alone does not prevent a valid code from being used twice within the ~90-second window. Use `auth.TOTPUsedCodeCache` (zero value is ready to use) in `TOTPHandler` to block replays:

```go
var usedCodes auth.TOTPUsedCodeCache // process-local; zero value ready to use

if usedCodes.WasUsed(userID, code) {
    // reject
}
// ... validate code ...
usedCodes.MarkUsed(userID, code)
```

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
    RefreshTokenTTL:   handler.DefaultRefreshTokenTTL, // defaults to 7 days when Sessions is set
    RefreshCookieName: "refresh",  // optional; stores refresh token in an HttpOnly cookie
    RequireVerification: true,     // optional; rejects login for unverified email addresses
    Verifications:     verificationStore, // required when EmailVerificationHandler is mounted
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

#### Response types

`Signup`, `Login`, and `RefreshToken` return an auth response wrapper that includes `user: handler.UserDTO`, while `Me` and `UpdateProfile` return a bare `handler.UserDTO`:

```go
type UserDTO struct {
    ID            string `json:"id"`
    Name          string `json:"name"`
    Email         string `json:"email"`
    OIDCLinked    bool   `json:"oidc_linked"`
    IsAdmin       bool   `json:"is_admin"`
    EmailVerified bool   `json:"email_verified"`
}

// Convert an auth.User to a UserDTO (useful in custom handlers or tests).
dto := handler.ToUserDTO(user)
```

`Signup`, `Login`, and `RefreshToken` return an `AuthResponse` containing `token`, `refresh_token` (when Sessions is set), and `user` (a `UserDTO`).

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

`Callback` does **not** return JSON. On success it sets the JWT in an `HttpOnly` session cookie and redirects the browser to `/?oidc_login=1` (HTTP 302) so that single-page applications can detect a completed OIDC login via the query parameter. The redirect destination is currently fixed; frontends that need a custom post-login URL should rely on the `oidc_login=1` query parameter (or another explicit non-`HttpOnly` signal) to trigger navigation, rather than attempting to read the session cookie from browser JavaScript.

> **No session tracking or refresh tokens.** `OIDCHandler` does not have a `Sessions` field and always issues a plain short-lived JWT. If you need server-side session revocation and refresh-token rotation for OIDC logins, do not use the built-in `Callback` as-is; implement a custom callback flow that completes the OIDC exchange, creates a session, and issues tokens with the session-aware JWT API (for example, `JWTManager.CreateTokenWithSession`) together with your refresh-token flow.

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

#### Response types

`List` returns a JSON array of key metadata objects. `Create` returns the same shape plus a `key` field containing the full raw key (returned exactly once):

```go
// Illustrative response shapes (actual types are unexported in the handler package)

// Returned by List (and by Create, which also includes Key)
type apiKeyDTO struct {
    ID         string     `json:"id"`
    Name       string     `json:"name"`
    KeyPrefix  string     `json:"key_prefix"` // configured prefix + first 12 hex chars of the random portion
    LastUsedAt *time.Time `json:"last_used_at"` // null until first use
    CreatedAt  time.Time  `json:"created_at"`
}

// Returned by Create only
type apiKeyCreateResponse struct {
    apiKeyDTO
    Key string `json:"key"` // full raw API key; present in Create response only
}
```

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

```go
type SessionDTO struct {
    ID         string    `json:"id"`
    UserAgent  string    `json:"user_agent"`
    IPAddress  string    `json:"ip_address"`
    ExpiresAt  time.Time `json:"expires_at"`
    CreatedAt  time.Time `json:"created_at"`
}
```

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

#### Response types

`FinishAuthentication` returns HTTP 200 with an `AuthResponse` (`token` + `user`) **and** sets the JWT in an `HttpOnly` session cookie (same cookie name as `CookieName`). There is no `refresh_token` field — `PasskeyHandler` does not have a `Sessions` field and always issues a plain short-lived JWT. To enable server-side sessions and refresh-token rotation for passkey logins, create a session and re-issue the JWT manually after `FinishAuthentication` succeeds.

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


### TOTPHandler – TOTP / MFA

```go
h := &handler.TOTPHandler{
    TOTP:      totpStore,
    Users:     userStore,
    Issuer:    "MyApp",
    UsedCodes: auth.TOTPUsedCodeCache{}, // zero value is ready to use; prevents replay attacks
}

// Authenticated routes
POST   /totp/generate   → h.Generate   // generate secret + provisioning URI (not persisted)
POST   /totp/enroll     → h.Enroll     // verify first code and persist the secret
POST   /totp/verify     → h.Verify     // verify a code against the enrolled secret
GET    /totp/status     → h.Status     // check whether TOTP is enrolled
DELETE /totp            → h.Disable    // remove enrolled secret (204 No Content)
```

Enrollment is a two-step flow: `Generate` returns a secret and `otpauth://` URI for the QR code, then `Enroll` verifies the first code from the authenticator app and persists the secret. `UsedCodes` provides process-local replay protection within the ~90-second TOTP validity window.

#### Response types

| Route | HTTP status | Response body |
|---|---|---|
| `Generate` | 200 | `{"secret": "...", "provisioning_uri": "otpauth://..."}` — `Cache-Control: no-store` |
| `Enroll` | 200 | `{"enrolled": true}` |
| `Verify` | 200 | `{"valid": true}` |
| `Status` | 200 | `{"enrolled": <bool>}` |
| `Disable` | 204 | *(no body)* |

### MagicLinkHandler – passwordless login

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

POST /auth/magic-link/request   → h.RequestMagicLink   // send one-time login link (200 whether or not email is registered)
GET  /auth/magic-link/verify    → h.VerifyMagicLink    // ?token=<token> → AuthResponse (HTTP 200)
```

Tokens expire after 15 minutes. `VerifyMagicLink` auto-provisions a new account when no user exists for the email address. `RequestMagicLink` returns the same success response whether or not the email is registered, preventing enumeration; validation and operational errors still surface as non-200 responses.

#### Response types

`VerifyMagicLink` returns HTTP 200 with the same `AuthResponse` wrapper as `AuthHandler.Login` — `token`, `refresh_token` (when `Sessions` is set), and `user` (`UserDTO`). It also sets an `HttpOnly` session cookie and, when `Sessions` is set and `RefreshCookieName` is non-empty, an `HttpOnly` refresh token cookie.

`RequestMagicLink` returns HTTP 200 with `{"message": "if that email is valid, a login link has been sent"}`.

Session tracking and refresh token rotation work identically to `AuthHandler` — set `Sessions`, `RefreshTokenTTL`, and `RefreshCookieName` to enable them.

### EmailVerificationHandler – email address verification

```go
h := &handler.EmailVerificationHandler{
    Users:         userStore,
    Verifications: verificationStore,
    SendEmail:     func(ctx context.Context, to, token string) error { /* send email */ return nil },
    TokenTTL:      24 * time.Hour, // defaults to 24 hours
}

POST /verify-email/send   → h.SendVerification   // send verification email (200 whether or not email is registered)
GET  /verify-email        → h.VerifyEmail         // ?token=<token> → marks email verified
```

`SendVerification` silently skips already-verified addresses and returns the same success response whether or not the address is registered, preventing enumeration. Set `RequireVerification: true` on `AuthHandler` to gate login on email verification.

When `SendEmail` is `nil`, verification tokens are still created and stored but no email is delivered. This is useful in testing environments where email delivery is not required.

### PasswordResetHandler – email-based password reset

```go
h := &handler.PasswordResetHandler{
    Users:          userStore,
    Resets:         passwordResetStore,
    SendResetEmail: func(ctx context.Context, toEmail, rawToken string) error { /* send email */ return nil },
    TokenTTL:       time.Hour, // defaults to 1 hour
    RateLimiter:    rl,        // optional; recommended to limit abuse
}

POST /password-reset/request   → h.RequestReset    // send reset email (200 whether or not email is registered)
POST /password-reset/confirm   → h.ResetPassword   // validate token and set new password
```

Only accounts with a password hash (not OIDC-only accounts) can use the reset flow. `RequestReset` returns the same success response whether or not the email is registered. Reset tokens are consumed (deleted) after successful use.

### Cookie helpers

```go
handler.SetAuthCookie(w, token, cookieName, secure)         // HttpOnly, SameSite=Strict
handler.ClearAuthCookie(w, cookieName, secure)
handler.SetRefreshCookie(w, token, cookieName, secure, maxAge) // HttpOnly, SameSite=Strict
handler.ClearRefreshCookie(w, cookieName, secure)
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

- Each cleaner runs once immediately when `StartCleanup` is called, then once per `interval`. Each cleaner is called with the context passed to `StartCleanup`.
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
- **Password reset** – Reset tokens are bound to accounts that have a password hash. OIDC-only accounts cannot use the password reset flow.
- **Email enumeration** – `RequestMagicLink`, `RequestReset`, and `SendVerification` return the same success response whether or not the email is registered, preventing enumeration via timing or response differences. Validation and operational errors still surface as non-200 responses.
