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
// secret  – signing secret (recommended: at least auth.MinSecretLength (32) bytes; empty → random, tokens won't survive restarts)
// ttl     – token lifetime (e.g. 24 * time.Hour)
// issuer  – value used for iss/aud claims (defaults to "goauth")

token, err := jwtMgr.CreateToken(ctx, userID)
// CreateTokenWithSession embeds the session ID as the JWT jti claim.
// Use this (or let AuthHandler do it automatically) when Sessions is enabled.
token, err = jwtMgr.CreateTokenWithSession(ctx, userID, sessionID)

tokenString := token // signed JWT string returned by CreateToken / CreateTokenWithSession

claims, err := jwtMgr.ValidateToken(ctx, tokenString)
// claims is of type *auth.Claims:
//   type Claims struct {
//       UserID string `json:"sub"` // subject (user ID)
//       jwt.RegisteredClaims       // embeds ID (jti), ExpiresAt, IssuedAt, Issuer, Audience
//   }
// claims.UserID contains the subject; claims.ID contains the session ID (jti)

// ParseTokenClaims validates the signature (and iss/aud) but ignores all
// time-based claim validation (expiry, not-before, issued-at).
// Useful for logout or audit flows that need the session ID from a token
// that may be expired, not yet valid, or otherwise outside time-based checks.
claims, err = jwtMgr.ParseTokenClaims(tokenString)

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

| Error | Description |
|---|---|
| `auth.ErrInvalidToken` | Token signature or structure is invalid |
| `auth.ErrExpiredToken` | Token has passed its `exp` claim |
| `auth.ErrEmailExists` | `CreateUser` called with an already-registered email |
| `auth.ErrEmailNotVerified` | Provided for consuming applications and custom middleware; not returned by built-in handlers (which write HTTP 403 directly) |
| `auth.ErrSessionRevoked` | Provided for consuming applications and custom middleware; not returned by the built-in `Middleware`, which handles the HTTP response directly |
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
router.Use(auth.Middleware(jwtMgr, cfg, apiKeyStore))

// Require admin on a route group.
// The second argument is an auth.AdminChecker:
//   type AdminChecker interface {
//       IsAdmin(ctx context.Context, userID string) (bool, error)
//   }
// UserStore satisfies AdminChecker via its IsAdmin method.
router.Use(auth.AdminMiddleware(jwtMgr, userStore, cfg, apiKeyStore))

// Require a specific role or permission on a route group (see RBAC below).
// The second argument is an auth.RoleChecker:
//   type RoleChecker interface {
//       HasRole(ctx context.Context, userID string, role auth.Role) (bool, error)
//       HasPermission(ctx context.Context, userID string, perm auth.Permission) (bool, error)
//   }
// Use auth.NewStoreRoleChecker or auth.NewCachingRoleChecker to build one (see RBAC below).
router.Use(auth.RequireRole(jwtMgr, roleChecker, cfg, apiKeyStore, auth.RoleEditor))
router.Use(auth.RequirePermission(jwtMgr, roleChecker, cfg, apiKeyStore, auth.PermWriteContent))

// Read the resolved user ID anywhere downstream.
userID := auth.UserIDFromContext(req.Context())

// ContextWithUserID injects a user ID into a context manually.
// Useful in tests or custom middleware that bypass the standard auth flow.
ctx := auth.ContextWithUserID(req.Context(), userID)

// Store/retrieve arbitrary roles in context for downstream handlers.
ctx = auth.ContextWithRoles(ctx, []auth.Role{auth.RoleAdmin})
roles := auth.RolesFromContext(ctx)

// ExtractToken reads the raw token string from a request without validating it.
// Checks the Authorization: Bearer header first, then falls back to the named cookie.
// Useful in custom middleware or logout/revocation handlers that need the raw token.
tok := auth.ExtractToken(req, cfg.CookieName) // "" if absent
```

All four middleware variants (`Middleware`, `AdminMiddleware`, `RequireRole`, `RequirePermission`) use the same token extraction and session validation logic. JWTs are accepted from the `Authorization: Bearer <token>` header or from the configured cookie. API keys are accepted **only** from the `Authorization: Bearer <token>` header (that is, the API key must be provided as the bearer token, not as a raw `Authorization: <apiKey>` value), and are not read from cookies.

`AdminMiddleware` caches admin status checks (via `AdminChecker.IsAdmin`) for **5 seconds** per user ID (up to **4,096** entries per process; the oldest-inserted entry is evicted when the cache is full; expired entries are purged at most once per minute). `RequireRole` and `RequirePermission` each maintain an internal `CachingRoleChecker` with the same **5-second** TTL.

When `Sessions` is set, the middleware validates the JWT `jti` claim against the store and rejects requests whose session has been revoked or expired server-side. API key requests bypass the session check.

#### Observability

All four middleware functions — `Middleware`, `AdminMiddleware`, `RequireRole`, and `RequirePermission` — share the same authentication path and emit the same structured log events via the standard library's `log/slog` package, propagating the request context for trace correlation.

| Event | Level | `slog` message |
|---|---|---|
| Token absent from header and cookie | `INFO` | `"authentication required"` |
| `TouchAPIKeyLastUsed` store call fails | `WARN` | `"failed to touch API key last_used_at"` |
| Unexpected error from `resolveUser` | `ERROR` | `"failed to resolve user"` |
| Unexpected error from `FindSessionByID` | `ERROR` | `"failed to look up session"` |

`ErrInvalidToken` and `ErrExpiredToken` are **not** logged — they are treated as expected conditions and produce a `401` response with no log noise.

goauth never sets or replaces the global `slog` handler. Configure your own handler before starting the server to control log destination, format, and minimum level.

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

`NewCachingRoleChecker` holds up to **4,096** role-check results and **4,096** permission-check results per process. When either cache is full, the oldest-inserted entry is evicted (FIFO). During cache writes, expired entries are purged at most once per minute. Passing `ttl <= 0` uses the default middleware TTL of 5 seconds.

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

When `trustedProxies` is set and the direct peer IP matches a trusted CIDR, the limiter reads the `X-Forwarded-For` header and applies a **right-to-left scan** — it picks the rightmost IP that is *not* in the trusted set. This mirrors the "trusted-leftmost-forwarder" model recommended for multi-hop reverse-proxy chains and avoids accepting a client-supplied IP from the leftmost, untrusted part of the header.

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

`SecretEncrypter` is safe for concurrent use. Both the AES block cipher and the `cipher.AEAD` (GCM) instance are created once at construction time and reused across all `Encrypt` and `Decrypt` calls. Go's AES-GCM implementation does not share mutable state between concurrent `Seal`/`Open` invocations, so a single cached instance is safe. The raw derived key is zeroed immediately after the cipher is created.

```go
enc, err := jwtMgr.NewSecretEncrypter()

ciphertext, err := enc.Encrypt("sensitive value")
plaintext, err  := enc.Decrypt(ciphertext)
// Decrypt is a no-op if the value doesn't start with the "enc:v1:" prefix.
// Encrypt and Decrypt return an error if called on a zero-value SecretEncrypter.
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

The middleware calls `TouchAPIKeyLastUsed` at most once every **5 minutes** per key ID per process to reduce write pressure on the store. In single-process deployments, implementations do not need to debounce it themselves; in multi-process deployments each instance throttles independently.

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

`FinishAuthentication` attempts to call `UpdateCredentialData` after a successful WebAuthn assertion to persist the updated sign counter, but only if the updated credential data can be marshaled successfully. Failures are non-fatal (authentication still succeeds), and marshal/store problems are logged as warnings — see the `FinishAuthentication` notes below.

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

**Replay protection** – `ValidateTOTP` alone does not prevent a valid code from being used twice within the ~90-second window. Pass `&auth.TOTPUsedCodeCache{}` to `TOTPHandler.UsedCodes` to block replays (see the `TOTPHandler` section below). For standalone use outside a handler, the zero value is ready to use directly:

```go
var usedCodes auth.TOTPUsedCodeCache // process-local; zero value ready to use directly

if usedCodes.WasUsed(userID, code) {
    // reject
}
// ... validate code ...
usedCodes.MarkUsed(userID, code)
```

---

## `handler` package

All handlers use `net/http` only and are compatible with any router. Router-specific helpers (e.g. URL parameter extraction) are injected via a `func(r *http.Request, key string) string` field.

> **Request body limit** – endpoints that decode JSON via the shared `decodeJSON` helper enforce a **1 MiB** maximum and reject larger requests with `400 Bad Request`. Passkey finish endpoints (`PasskeyHandler.FinishRegistration` and `PasskeyHandler.FinishAuthentication`) do not use `decodeJSON` in this package, so this limit does not apply to them here.

### AuthHandler – email/password

```go
h := &handler.AuthHandler{
    Users:             userStore,
    JWT:               jwtMgr,
    CookieName:        "session",
    SecureCookies:     true,
    DisableSignup:     false,    // set true to prevent self-registration
    Sessions:          sessionStore, // optional; enables session tracking and refresh tokens
    RefreshTokenTTL:   handler.DefaultRefreshTokenTTL, // 7-day default (handler.DefaultRefreshTokenTTL); only used when Sessions is set
    RefreshCookieName: "refresh",  // optional; stores refresh token in an HttpOnly cookie
    RequireVerification: true,     // optional; rejects login for unverified email addresses
}

// Routes
POST   /auth/signup          → h.Signup         // 201 Created; token + user (+ refresh_token when Sessions set)
POST   /auth/login           → h.Login          // token + user (+ refresh_token when Sessions set)
POST   /auth/logout          → h.Logout         // clears cookie; revokes session when Sessions set → {"message":"logged out"}
POST   /auth/refresh         → h.RefreshToken   // rotate refresh token → new access + refresh token (requires Sessions; 404 when Sessions is nil)
GET    /auth/me              → h.Me             // current user profile (requires auth)
PUT    /auth/me              → h.UpdateProfile  // update display name (requires auth)
POST   /auth/password        → h.ChangePassword // change password (requires auth) → {"message":"password updated"}
```

Password constraints: 8–72 bytes. Bcrypt cost 12.

#### Response types

`Signup`, `Login`, and `RefreshToken` return an `AuthResponse` wrapper, while `Me` and `UpdateProfile` return a bare `handler.UserDTO`:

```go
type AuthResponse struct {
    Token        string  `json:"token"`
    RefreshToken string  `json:"refresh_token,omitempty"` // present only when Sessions is set
    User         UserDTO `json:"user"`
}

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

`Signup`, `Login`, and `RefreshToken` return an `AuthResponse` containing `token`, `refresh_token` (when Sessions is set), and `user` (a `UserDTO`). All three endpoints set `Cache-Control: no-store` and `Pragma: no-cache` on success responses to prevent caching of authentication tokens.

#### Request bodies

`Signup`, `Login`, `UpdateProfile`, `ChangePassword`, and `RefreshToken` read a JSON body. When `RefreshCookieName` is set, `RefreshToken` prefers the cookie and falls back to the body only when the cookie is absent:

```go
// POST /auth/signup
type signupRequest struct {
    Name     string `json:"name"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

// POST /auth/login
type loginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

// PUT /auth/me (requires auth)
type updateProfileRequest struct {
    Name string `json:"name"`
}

// POST /auth/password (requires auth)
type changePasswordRequest struct {
    CurrentPassword string `json:"currentPassword"`
    NewPassword     string `json:"newPassword"`
}

// POST /auth/refresh — body used when RefreshCookieName is not set or cookie is absent
type refreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}
```

`Signup`, `Login`, and `RefreshToken` set `Cache-Control: no-store` and `Pragma: no-cache` on success.


#### Error responses

All `AuthHandler` endpoints return `{"error": "<message>"}` JSON on failure.

| Endpoint | Status | Condition |
|---|---|---|
| `Signup` | `400 Bad Request` | Invalid JSON body, any of `name`, `email`, or `password` is missing, or password is outside 8–72 bytes |
| `Signup` | `403 Forbidden` | `DisableSignup` is `true` |
| `Signup` | `409 Conflict` | Email address already registered (`auth.ErrEmailExists`) |
| `Signup` | `500 Internal Server Error` | bcrypt failure, store error creating user, or token/session issuance failure (refresh-token generation, session creation, or JWT creation) |
| `Login` | `400 Bad Request` | Invalid JSON body, or `email` or `password` is empty |
| `Login` | `401 Unauthorized` | Email not found, wrong password, or account is OIDC-only (no password hash) |
| `Login` | `403 Forbidden` | `RequireVerification` is `true` and the account's `EmailVerified` is `false` |
| `Login` | `500 Internal Server Error` | Store error looking up user, or token/session issuance failure (session creation or JWT creation) |
| `Logout` | 200 always | Clears the cookie; session revocation errors are silently ignored |
| `RefreshToken` | `400 Bad Request` | Refresh token not present in cookie or request body |
| `RefreshToken` | `401 Unauthorized` | Token not found in store, token is expired, or associated user not found |
| `RefreshToken` | `404 Not Found` | `Sessions` is `nil` (refresh tokens not enabled) |
| `RefreshToken` | `500 Internal Server Error` | Store error or JWT creation failure |
| `Me` | `404 Not Found` | User not found (e.g. deleted since the token was issued) |
| `Me` | `500 Internal Server Error` | Store error |
| `UpdateProfile` | `400 Bad Request` | Invalid JSON body or `name` is empty |
| `UpdateProfile` | `500 Internal Server Error` | Store error updating name |
| `ChangePassword` | `400 Bad Request` | Invalid JSON body, `currentPassword` or `newPassword` missing, password outside 8–72 bytes, or account has no password hash (OIDC-only) |
| `ChangePassword` | `401 Unauthorized` | `currentPassword` does not match the stored hash |
| `ChangePassword` | `500 Internal Server Error` | Store or bcrypt error |

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

// Optional: enable server-side session tracking and refresh token rotation.
// When Sessions is set, RefreshCookieName must also be set (Callback returns
// 500 otherwise).
h.Sessions          = sessionStore
h.RefreshCookieName = "refresh"
h.RefreshTokenTTL   = 7 * 24 * time.Hour // defaults to handler.DefaultRefreshTokenTTL

// Routes
GET  /auth/oidc/login                  → h.Login              // redirects to provider
GET  /auth/oidc/callback               → h.Callback           // handles provider redirect
POST /auth/oidc/link-nonce             → h.CreateLinkNonce    // issue nonce for linking (requires auth)
GET  /auth/oidc/link?nonce=<nonce>     → h.Link               // start link flow (requires auth)
```

The callback performs PKCE verification and resolves the identity through the following ordered steps:

1. **Existing OIDC subject** — `FindByOIDCSubject` returns a user → log in immediately.
2. **Existing email** — `FindByEmail` returns a user → link the OIDC subject to that account (best-effort) and log in.
3. **New user** — `CreateOIDCUser` succeeds → log in with the new account.
4. **Concurrent-creation race** — `CreateOIDCUser` returns `auth.ErrEmailExists` (another concurrent request already created the account) → retry `FindByOIDCSubject` and `FindByEmail` to resolve the user, then continue normally: log in if the subject is found, or best-effort link the subject and log in if resolution succeeds via `FindByEmail`.

Any other error from `CreateOIDCUser` (for example, a database connection failure or check-constraint violation) is returned immediately as a 500. It is **not** silently retried, so the original error is always preserved in the server logs.

Account linking uses a short-lived (5-minute) HMAC-signed state token so the user's browser never sees the user ID in plaintext.

`NewOIDCHandler` always requests the `openid`, `email`, and `profile` scopes. The provider must expose an email claim; the `profile` scope is requested so the provider may return a display name for new account creation.

`Callback` does **not** return JSON on success — it sets the JWT in an `HttpOnly` session cookie and redirects the browser to `/?oidc_login=1` (HTTP 302) so that single-page applications can detect a completed OIDC login via the query parameter. On failure, `Callback` returns a JSON error body. The redirect destination is currently fixed; frontends that need a custom post-login URL should rely on the `oidc_login=1` query parameter (or another explicit non-`HttpOnly` signal) to trigger navigation, rather than attempting to read the session cookie from browser JavaScript.

When `Sessions` is set on `OIDCHandler`, `Callback` creates a server-side session and returns a refresh token alongside the short-lived access token, identical to the behaviour of `AuthHandler`. **When `Sessions` is set, `RefreshCookieName` must also be non-empty**; `Callback` returns `500 Internal Server Error` if this constraint is violated. Session tracking and refresh token rotation follow the same rules as `AuthHandler` — see [Session tracking and refresh token rotation](#session-tracking-and-refresh-token-rotation).

`CreateLinkNonce` returns HTTP 200 with `{"nonce": "<nonce>"}`. Pass the nonce as the `nonce` query parameter to the `Link` route within 5 minutes to start the account-linking flow.

`Link` redirects the browser to the OIDC provider (HTTP 302) using PKCE, just like `Login`. When the provider redirects back to `Callback`, the handler detects the link-in-progress state and redirects to:

| Outcome | Redirect |
|---|---|
| Success | `/?oidc_linked=true` |
| User not found | `/?oidc_link_error=User+not+found` |
| Account already linked | `/?oidc_link_error=Already+linked` |
| SSO identity taken by another account | `/?oidc_link_error=SSO+identity+linked+to+another+account` |
| Store failure | `/?oidc_link_error=Failed+to+link` |

> **Note:** The table above covers only the outcomes handled inside `handleLinkCallback`. Errors that occur earlier in the OIDC exchange — such as the provider returning an `error` query parameter (e.g. the user cancels on the consent screen), a missing `code`, a failed token exchange, or an invalid `id_token` — are surfaced as JSON error responses (HTTP 400, 401, or 500 as appropriate) rather than redirects. Clients must handle both redirect and JSON error outcomes.

#### Error responses

OIDC endpoints use `{"error": "<message>"}` JSON for non-redirect failure responses. `Login` and `Callback` may return JSON errors or redirect-based errors depending on the phase of the flow. The `Link` endpoint returns JSON errors.

| Endpoint | Status / Redirect | Condition |
|---|---|---|
| `Login` | `500 Internal Server Error` | Failed to generate OAuth state |
| `Callback` | `500 Internal Server Error` (JSON) | `Sessions` is set but `RefreshCookieName` is empty (misconfiguration) |
| `Callback` | `400 Bad Request` (JSON) | Missing state cookie, invalid state parameter, missing PKCE verifier, missing `authorization_code`, or missing required `sub`/`email` claims |
| `Callback` | `401 Unauthorized` (JSON) | OIDC provider returned an error (e.g. user denied consent), token exchange failed, missing or invalid `id_token`, or OIDC provider did not verify the email |
| `Callback` | `500 Internal Server Error` (JSON) | Failed to parse claims, store error during user resolution or creation, failed to resolve the OIDC user after the `auth.ErrEmailExists` race-retry path, or JWT creation failed |
| `Callback` (link flow) | Redirect `/?oidc_link_error=…` | User not found, subject already linked to this account, subject already linked to another account, or link store error |
| `Callback` (link flow) | Redirect `/?oidc_linked=true` | Account linking succeeded |
| `CreateLinkNonce` | `500 Internal Server Error` | Nonce generation failed |
| `Link` | `400 Bad Request` | `nonce` query parameter is missing |
| `Link` | `401 Unauthorized` | Nonce is invalid or expired |
| `Link` | `409 Conflict` | User lookup failed or user not found; account already has an OIDC subject linked |
| `Link` | `500 Internal Server Error` | Failed to generate OAuth state |

### APIKeyHandler

```go
h := &handler.APIKeyHandler{
    APIKeys:      apiKeyStore,
    Prefix:       "myapp_",   // prepended to the random hex token
    URLParamFunc: chi.URLParam,
}

// Routes (all require auth middleware)
GET    /api-keys        → h.List    // list keys (prefix + metadata only, never the raw key)
POST   /api-keys        → h.Create  // 201 Created; raw key returned once, never again
DELETE /api-keys/{id}   → h.Delete  // 204 No Content
```

Keys are 160-bit random values prefixed with the configured string. Only the SHA-256 hash is persisted. The raw key is returned in the `key` field of the creation response only.

`Create` expects `{"name": "<display name>"}`. The name must be 1–100 characters (non-empty after trimming).

#### Response types

| Route | HTTP status | Response body |
|---|---|---|
| `List` | 200 | `[]apiKeyDTO` — array of key metadata |
| `Create` | 201 | `apiKeyDTO` + `key` field — `Cache-Control: no-store` and `Pragma: no-cache` |
| `Delete` | 204 | *(no body)* |

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

The `Create` response embeds `apiKeyDTO` and adds a top-level `key` field containing the full plaintext key. `key_prefix` is the configured `Prefix` followed by the first 12 hex characters of the key — safe to display for user-facing identification.

#### Error responses

| Endpoint | Status | Condition |
|---|---|---|
| `List` | `500 Internal Server Error` | Store error while listing keys |
| `Create` | `400 Bad Request` | `name` is empty or exceeds 100 characters |
| `Create` | `500 Internal Server Error` | Key generation or store error |
| `Delete` | `400 Bad Request` | API key ID missing from URL |
| `Delete` | `404 Not Found` | API key not found or does not belong to the authenticated user |
| `Delete` | `500 Internal Server Error` | Store error while deleting key |


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

#### Error responses

| Endpoint | Status | Condition |
|---|---|---|
| `List` | `500 Internal Server Error` | Store error while listing sessions |
| `Revoke` | `400 Bad Request` | Session ID missing from URL |
| `Revoke` | `404 Not Found` | Session not found or does not belong to the authenticated user |
| `Revoke` | `500 Internal Server Error` | Store error while revoking session |
| `RevokeAll` | `500 Internal Server Error` | Store error while revoking all sessions |

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
GET  /auth/passkey/enabled                → h.Enabled              // {"enabled": true|false}
POST /auth/passkey/login/begin            → h.BeginAuthentication  // {"session_id":"…","options":{…}}
POST /auth/passkey/login/finish           → h.FinishAuthentication // ?session_id=<id>

// Authenticated routes
POST /auth/passkey/register/begin         → h.BeginRegistration    // {"session_id":"…","options":{…}}
POST /auth/passkey/register/finish        → h.FinishRegistration   // ?session_id=<id>
GET  /auth/passkey/credentials            → h.ListCredentials
DELETE /auth/passkey/credentials/{id}     → h.DeleteCredential     // 204 No Content
```

Registration and authentication use server-side challenge storage (via `PasskeyStore`) instead of cookies, keeping the flow stateless on the client. Discoverable login is used so users do not need to enter an identifier before presenting a passkey. Challenges expire after **5 minutes**; `FinishRegistration` and `FinishAuthentication` reject any `session_id` whose challenge has expired.

#### Request bodies

`BeginRegistration` expects `{"name": "<passkey name>"}`. The name is required and must be 1–100 bytes (non-empty after trimming). No request body is required for `BeginAuthentication`.

`FinishRegistration` and `FinishAuthentication` do not define their own JSON schema — the request body is passed directly to the WebAuthn library (`go-webauthn`), which expects a JSON-encoded `PublicKeyCredential` as produced by the browser's WebAuthn API. The `session_id` is accepted as a query parameter.

#### Response types

`BeginRegistration` and `BeginAuthentication` both return HTTP 200 with a begin-ceremony response. Pass `session_id` as the `session_id` query parameter to the corresponding finish endpoint, and pass `options` to the browser's WebAuthn API (`navigator.credentials.create` for registration, `navigator.credentials.get` for authentication):

```json
{
  "session_id": "<opaque-id>",
  "options": { /* WebAuthn PublicKeyCredentialCreationOptions or PublicKeyCredentialRequestOptions */ }
}
```

| Route | HTTP status | Response body |
|---|---|---|
| `Enabled` | 200 | `{"enabled": <bool>}` |
| `BeginRegistration` | 200 | `{"session_id": "...", "options": {...}}` — WebAuthn `PublicKeyCredentialCreationOptions` |
| `FinishRegistration` | 201 | `PasskeyCredentialDTO` |
| `BeginAuthentication` | 200 | `{"session_id": "...", "options": {...}}` — WebAuthn `PublicKeyCredentialRequestOptions` |
| `FinishAuthentication` | 200 | `AuthResponse` (`token` + `user`) — also sets `HttpOnly` session cookie |
| `ListCredentials` | 200 | `[]PasskeyCredentialDTO` |
| `DeleteCredential` | 204 | *(no body)* |

`FinishAuthentication` returns HTTP 200 with an `AuthResponse` (`token` + `user`) **and** sets the JWT in an `HttpOnly` session cookie (same cookie name as `CookieName`). There is no `refresh_token` field — `PasskeyHandler` does not have a `Sessions` field and always issues a plain short-lived JWT. To enable server-side sessions and refresh-token rotation for passkey logins, create a session and re-issue the JWT manually after `FinishAuthentication` succeeds.

> **Sign-counter update is best-effort.** After a successful WebAuthn assertion, `FinishAuthentication` attempts to call `PasskeyStore.UpdateCredentialData` to persist the updated sign counter, but only if the updated credential data can be marshaled successfully. If the `json.Marshal` step or the store call fails, a `slog.WarnContext` log entry is emitted with `user_id` and `credential_id` fields — but **authentication is not blocked**: the handler still returns HTTP 200 with the `AuthResponse`. Monitor for the log messages `"failed to marshal credential for counter update"` and `"failed to update credential counter"` to detect persistent store issues.

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

#### Error responses

All passkey endpoints return `{"error": "<message>"}` JSON on failure. The table below lists the non-200 status codes each endpoint can produce.

| Endpoint | Status | Condition |
|---|---|---|
| `BeginRegistration`, `FinishRegistration`, `BeginAuthentication`, `FinishAuthentication` | `503 Service Unavailable` | `WebAuthn` field is `nil` (passkeys not configured) |
| `BeginRegistration` | `400 Bad Request` | Invalid JSON request body, `name` is empty, or `name` exceeds 100 characters |
| `BeginRegistration` | `500 Internal Server Error` | User lookup failed, credential list failure (`ListCredentialsByUser`), WebAuthn ceremony error, or challenge storage error |
| `FinishRegistration` | `400 Bad Request` | `session_id` query parameter missing, session not found, session expired, or session belongs to a different user |
| `FinishRegistration` | `400 Bad Request` | WebAuthn attestation verification failed |
| `FinishRegistration` | `500 Internal Server Error` | User lookup failed, credential marshal failure, credential list failure (`ListCredentialsByUser`), or credential storage failed |
| `BeginAuthentication` | `500 Internal Server Error` | WebAuthn ceremony error or challenge storage error |
| `FinishAuthentication` | `400 Bad Request` | `session_id` query parameter missing |
| `FinishAuthentication` | `401 Unauthorized` | Session not found, session expired, credential not found, user lookup failed, or WebAuthn assertion verification failed |
| `FinishAuthentication` | `500 Internal Server Error` | `ListCredentialsByUser` store error during authentication, or JWT creation failed |
| `ListCredentials` | `500 Internal Server Error` | Store error while listing credentials |
| `DeleteCredential` | `400 Bad Request` | Credential ID missing from URL |
| `DeleteCredential` | `404 Not Found` | Credential not found or does not belong to the authenticated user |
| `DeleteCredential` | `500 Internal Server Error` | Store error while deleting credential |


### TOTPHandler – TOTP / MFA

```go
h := &handler.TOTPHandler{
    TOTP:      totpStore,
    Users:     userStore,
    Issuer:    "MyApp",
    UsedCodes: &auth.TOTPUsedCodeCache{}, // required; prevents replay attacks
}

// Authenticated routes
POST   /totp/generate   → h.Generate   // generate secret + provisioning URI (not persisted)
POST   /totp/enroll     → h.Enroll     // verify first code and persist the secret
POST   /totp/verify     → h.Verify     // verify a code against the enrolled secret
GET    /totp/status     → h.Status     // check whether TOTP is enrolled
DELETE /totp            → h.Disable    // remove enrolled secret (204 No Content)
```

Enrollment is a two-step flow: `Generate` returns a secret and `otpauth://` URI for the QR code, then `Enroll` verifies the first code from the authenticator app and persists the secret. `UsedCodes` provides process-local replay protection within the ~90-second TOTP validity window.

#### Request bodies

`Enroll` and `Verify` read a JSON body from the request:

```go
// POST /totp/enroll
type totpEnrollRequest struct {
    Secret string `json:"secret"` // base32-encoded secret returned by Generate; must be a valid unpadded base32 string of at least 20 bytes (160 bits)
    Code   string `json:"code"`   // current 6-digit code from the authenticator app
}

// POST /totp/verify
type totpVerifyRequest struct {
    Code string `json:"code"` // current 6-digit code from the authenticator app
}
```

#### Response types

| Route | HTTP status | Response body |
|---|---|---|
| `Generate` | 200 | `{"secret": "...", "provisioning_uri": "otpauth://..."}` — with headers `Cache-Control: no-store` and `Pragma: no-cache` |
| `Enroll` | 200 | `{"enrolled": true}` |
| `Verify` | 200 | `{"valid": true}` |
| `Status` | 200 | `{"enrolled": <bool>}` |
| `Disable` | 204 | *(no body)* |

#### Error responses

All TOTP endpoints return `{"error": "<message>"}` JSON on failure. The table below lists the non-200 status codes each endpoint can produce.

| Endpoint | Status | Condition |
|---|---|---|
| `Generate` | `500 Internal Server Error` | Crypto failure generating the secret, or user lookup failed |
| `Enroll` | `400 Bad Request` | Invalid JSON body, `secret` or `code` field missing, `secret` is not a valid unpadded base32 value that decodes to at least 20 bytes, or `secret` fails TOTP validation |
| `Enroll` | `401 Unauthorized` | Code failed TOTP validation, or code was already used within the replay window |
| `Enroll` | `500 Internal Server Error` | Failed to persist the TOTP secret |
| `Verify` | `400 Bad Request` | Invalid JSON body or `code` field missing |
| `Verify` | `401 Unauthorized` | Code failed TOTP validation, or code was already used within the replay window |
| `Verify` | `404 Not Found` | No TOTP secret enrolled for the authenticated user |
| `Verify` | `500 Internal Server Error` | Store or validation error |
| `Status` | `500 Internal Server Error` | Store error |
| `Disable` | `404 Not Found` | No TOTP secret enrolled for the authenticated user |
| `Disable` | `500 Internal Server Error` | Store error |

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

The `Sender` field is of type `handler.MagicLinkSender` (`func(ctx context.Context, email, token string) error`). It must be set; a `nil` Sender causes `RequestMagicLink` to return `503 Service Unavailable` immediately — before any token is generated or written to `MagicLinks`. No unconsumed tokens accumulate in the store. In tests, use a no-op Sender (e.g., `func(ctx context.Context, email, token string) error { return nil }`) rather than leaving the field nil.

`RequestMagicLink` expects `{"email": "<address>"}` as its JSON request body. `VerifyMagicLink` accepts a `token` query parameter instead of a request body.

The `Sender` field has the named type `handler.MagicLinkSender` (`func(ctx context.Context, email, token string) error`). Assign any function with that signature to deliver the one-time token to the user via email or another channel.

Tokens expire after 15 minutes. `VerifyMagicLink` auto-provisions a new account when no user exists for the email address; the new account's display name is set to the email address. `RequestMagicLink` returns the same success response whether or not the email is registered, preventing enumeration; validation and operational errors still surface as non-200 responses.

#### Response types

`VerifyMagicLink` returns HTTP 200 with the same `AuthResponse` wrapper as `AuthHandler.Login` — `token`, `refresh_token` (when `Sessions` is set), and `user` (`UserDTO`). It also sets an `HttpOnly` session cookie and, when `Sessions` is set and `RefreshCookieName` is non-empty, an `HttpOnly` refresh token cookie. The response also sets `Cache-Control: no-store` and `Pragma: no-cache` to prevent caching of authentication tokens.

`RequestMagicLink` returns HTTP 200 with `{"message": "if that email is valid, a login link has been sent"}`.

`VerifyMagicLink` sets `Cache-Control: no-store` and `Pragma: no-cache` on success.

Session tracking and refresh token rotation work identically to `AuthHandler` — set `Sessions`, `RefreshTokenTTL`, and `RefreshCookieName` to enable them.

#### Request bodies

`RequestMagicLink` reads a JSON body. `VerifyMagicLink` reads its token from the `token` query parameter — no request body:

```go
// POST /auth/magic-link/request
type magicLinkRequestBody struct {
    Email string `json:"email"`
}
```

#### Error responses

All `MagicLinkHandler` endpoints return `{"error": "<message>"}` JSON on failure.

| Endpoint | Status | Condition |
|---|---|---|
| `RequestMagicLink` | `400 Bad Request` | Invalid JSON body or `email` is empty |
| `RequestMagicLink` | `500 Internal Server Error` | Token generation or store error |
| `RequestMagicLink` | `503 Service Unavailable` | `Sender` is `nil` (magic link sending not configured); no token is generated or stored |
| `VerifyMagicLink` | `400 Bad Request` | `token` query parameter is missing |
| `VerifyMagicLink` | `401 Unauthorized` | Token not found in store or token is expired |
| `VerifyMagicLink` | `500 Internal Server Error` | User lookup/creation or JWT creation failure |

> **Note:** When `Sender` is non-nil but returns an error, `RequestMagicLink` logs the failure and still returns HTTP 200. Email delivery failures do not surface as non-200 responses.

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

`SendVerification` expects `{"email": "<address>"}` as its JSON request body. `VerifyEmail` accepts a `token` query parameter instead of a request body.

`SendVerification` silently skips already-verified addresses and returns the same success response whether or not the address is registered, preventing enumeration. Set `RequireVerification: true` on `AuthHandler` to gate login on email verification.

When `SendEmail` is `nil`, verification tokens are still created and stored but no email is delivered. This is useful in testing environments where email delivery is not required.

#### Response types

| Route | HTTP status | Response body |
|---|---|---|
| `SendVerification` | 200 | `{"message": "if that address is registered, a verification email has been sent"}` |
| `VerifyEmail` | 200 | `{"message": "email verified"}` |

#### Request bodies

`SendVerification` reads a JSON body. `VerifyEmail` reads its token from the `token` query parameter — no request body:

```go
// POST /verify-email/send
type sendVerificationRequest struct {
    Email string `json:"email"`
}
```

#### Error responses

All `EmailVerificationHandler` endpoints return `{"error": "<message>"}` JSON on failure.

| Endpoint | Status | Condition |
|---|---|---|
| `SendVerification` | `400 Bad Request` | Invalid JSON body or `email` is empty |
| `VerifyEmail` | `400 Bad Request` | `token` query parameter is missing, or token is invalid or expired |
| `VerifyEmail` | `500 Internal Server Error` | Store error consuming or applying the verification |

> **Note:** Beyond the `400` cases, `SendVerification` always returns HTTP 200 — including when the user is not found, when the email is already verified, when token generation fails, when the store errors, and when email delivery fails. These failures are logged internally. This blanket 200 behaviour intentionally prevents leaking account existence.

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

Only accounts with a password hash (not OIDC-only accounts) can use the reset flow. `RequestReset` returns the same success response whether or not the email is registered. Reset tokens are consumed (deleted) after successful use. If `SendResetEmail` returns an error, the handler attempts to delete the orphaned token as a best-effort cleanup and still returns HTTP 200; deletion failures are only logged/ignored, so the token may remain in the store.

When `SendResetEmail` is `nil`, reset tokens are still created and stored but no email is delivered. This is useful in testing environments where email delivery is not required.

`RequestReset` expects `{"email": "<address>"}`. `ResetPassword` expects `{"token": "<raw token from email>", "newPassword": "<new password>"}` (same 8–72 byte password constraint as `AuthHandler`).

#### Response types

| Route | HTTP status | Response body |
|---|---|---|
| `RequestReset` | 200 | `{"message": "if that email is registered, a reset link has been sent"}` |
| `ResetPassword` | 200 | `{"message": "password reset successfully"}` |

#### Request bodies

```go
// POST /password-reset/request
type requestResetRequest struct {
    Email string `json:"email"`
}

// POST /password-reset/confirm
type resetPasswordRequest struct {
    Token       string `json:"token"`
    NewPassword string `json:"newPassword"`
}
```

#### Error responses

All `PasswordResetHandler` endpoints return `{"error": "<message>"}` JSON on failure.

| Endpoint | Status | Condition |
|---|---|---|
| `RequestReset` | `400 Bad Request` | Invalid JSON body or `email` is empty |
| `RequestReset` | `429 Too Many Requests` | Rate limiter triggered (when `RateLimiter` is set) |
| `RequestReset` | `500 Internal Server Error` | Store error looking up user, generating token, or persisting token |
| `ResetPassword` | `400 Bad Request` | Invalid JSON body, `token` missing, password outside 8–72 bytes, token invalid or expired, or account is OIDC-only (no password hash) |
| `ResetPassword` | `500 Internal Server Error` | User lookup, bcrypt, or store error |

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
- Errors returned by a cleaner are logged via `slog` at `ERROR` level with the fields `cleaner_name` and `error`. `cleaner_name` is usually the fully-qualified function name, but if the runtime cannot resolve one it falls back to a synthetic name such as `cleaner[0]`. Cleaners that panic are similarly recovered and logged with additional `panic` and `stack` fields.
- Log output uses the `slog.Logger` that was the process-wide default **at the time `StartCleanup` was called**, not at the time the cleaner runs. This means you can configure your logger before calling `StartCleanup` and the cleanup goroutine will use that logger for its entire lifetime.
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

`smtp.Send` uses a **10-second dial timeout** for the initial TCP connection. Once connected, an SMTP session deadline of **30 seconds** is set; context deadlines shorter than 30 seconds are honored. TLS connections (`tls` and `starttls` modes) require **TLS 1.2 or later**. Authentication uses PLAIN auth when both `SMTP_USERNAME` and `SMTP_PASSWORD` are non-empty; unauthenticated relay is used otherwise.

---

## Security notes

- **Secrets** – Pass a secret of at least `auth.MinSecretLength` (32) bytes to `NewJWTManager`. A shorter secret is accepted but not recommended.
- **Key material zeroisation** – `SecretEncrypter` zeros the HKDF-derived AES key immediately after the block cipher is initialised, reducing the window during which raw key bytes are live in memory.
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

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, test and lint commands, coding conventions, and the pull-request workflow.
