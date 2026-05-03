# Store Interfaces

The library defines store interfaces that consuming applications implement against their own database. Return `auth.ErrNotFound` (or wrap it) when a record is not found — handlers check for this sentinel to produce correct HTTP status codes.

## UserStore

```go
type UserStore interface {
    CreateUser(ctx context.Context, name, email, passwordHash string) (*User, error)
    CreateOIDCUser(ctx context.Context, name, email, oidcSubject string) (*User, error)
    FindByEmail(ctx context.Context, email string) (*User, error)
    FindByID(ctx context.Context, id string) (*User, error)
    FindByOIDCSubject(ctx context.Context, subject string) (*User, error)
    LinkOIDCSubject(ctx context.Context, userID, oidcSubject string) error
    UpdatePassword(ctx context.Context, userID, passwordHash string) error
    UpdateName(ctx context.Context, userID, name string) (*User, error)
    IsAdmin(ctx context.Context, userID string) (bool, error)
    CountUsers(ctx context.Context) (int, error)
}
```

Return `auth.ErrEmailExists` from `CreateUser` when a duplicate email is detected.

Return `auth.ErrEmailExists` from `CreateOIDCUser` when the given email is already registered. Both `OIDCHandler` and `OAuth2Handler` rely on this to handle a race condition where two concurrent first-time logins for the same email both attempt to create an account simultaneously: when `CreateOIDCUser` returns `ErrEmailExists`, the handler retries by looking up the now-existing user instead.

Implement `LinkOIDCSubject` as an idempotent upsert: return `nil` when the given OIDC subject is already associated with the specified user (i.e., the link is already in place). The interactive link callback treats any non-nil return value from `LinkOIDCSubject` as a failure, so returning `auth.ErrOIDCSubjectAlreadyLinked` here will cause a "Failed to link" redirect error on benign re-link attempts. The best-effort login path (`linkOIDCSubjectBestEffort`) does suppress `ErrOIDCSubjectAlreadyLinked` specifically, but an upsert returning `nil` is equally safe and avoids the callback-path failure. Return any other non-nil error for genuine failures (e.g. database errors).

### User struct

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

## APIKeyStore

```go
type APIKeyStore interface {
    CreateAPIKey(ctx context.Context, userID, name, keyHash, keyPrefix string) (*APIKey, error)
    ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error)
    FindAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*APIKey, error)
    ValidateAPIKey(ctx context.Context, keyHash string) (userID, apiKeyID string, err error)
    TouchAPIKeyLastUsed(ctx context.Context, id string) error
    DeleteAPIKey(ctx context.Context, id, userID string) error
}
```

`ValidateAPIKey` is given the SHA-256 hex hash of the raw key. Store only the hash — never the plaintext key.

### APIKey struct

```go
type APIKey struct {
    ID         string
    UserID     string
    Name       string
    KeyHash    string
    KeyPrefix  string
    LastUsedAt *time.Time // nil until the key has been used at least once
    CreatedAt  time.Time
}
```

## SessionStore

```go
type SessionStore interface {
    CreateSession(ctx context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*Session, error)
    FindSessionByID(ctx context.Context, id string) (*Session, error)
    FindSessionByRefreshTokenHash(ctx context.Context, hash string) (*Session, error)
    ListSessionsByUser(ctx context.Context, userID string) ([]Session, error)
    DeleteSession(ctx context.Context, id, userID string) error
    DeleteAllSessionsByUser(ctx context.Context, userID string) error
    DeleteExpiredSessions(ctx context.Context) error
}
```

Each session is bound to one refresh token hash. Only the SHA-256 hash of the refresh token is persisted.

Return `auth.ErrNotFound` from `FindSessionByID`, `FindSessionByRefreshTokenHash`, and `DeleteSession` when the record is not found.

**Session revocation**: have `FindSessionByID` return `auth.ErrNotFound` or `auth.ErrSessionRevoked` for sessions that are no longer valid; the middleware treats both as a `401 Unauthorized`. Hard-deleting the row (e.g. via `DeleteSession`) is the common approach, but soft-delete or audit-preserving schemes work equally well as long as `FindSessionByID` returns (or wraps) one of these sentinels for revoked sessions.

`FindSessionByRefreshTokenHash` may also return `auth.ErrSessionRevoked` when the session has been explicitly revoked; `RefreshToken` treats both `ErrNotFound` and `ErrSessionRevoked` as a `401 Unauthorized` with an `"invalid or expired refresh token"` message.

### Session struct

```go
type Session struct {
    ID               string
    UserID           string
    RefreshTokenHash string
    UserAgent        string
    IPAddress        string
    ExpiresAt        time.Time
    CreatedAt        time.Time
}
```

## PasskeyStore

```go
type PasskeyStore interface {
    CreateChallenge(ctx context.Context, userID *string, sessionData string, expiresAt time.Time) (*PasskeyChallenge, error)
    GetAndDeleteChallenge(ctx context.Context, id string) (*PasskeyChallenge, error)
    DeleteExpiredChallenges(ctx context.Context) error
    CreateCredential(ctx context.Context, userID, name, credentialID, credentialData, aaguid string) (*PasskeyCredential, error)
    ListCredentialsByUser(ctx context.Context, userID string) ([]PasskeyCredential, error)
    FindCredentialByCredentialID(ctx context.Context, credentialID string) (*PasskeyCredential, error)
    FindCredentialByIDAndUser(ctx context.Context, id, userID string) (*PasskeyCredential, error)
    UpdateCredentialData(ctx context.Context, userID, credentialID, credentialData string) error
    DeleteCredential(ctx context.Context, id, userID string) error
}
```

`userID` in `CreateChallenge` is `nil` during authentication (discoverable login) and non-nil during registration.

### PasskeyCredential struct

```go
type PasskeyCredential struct {
    ID             string
    UserID         string
    Name           string
    CredentialID   string // base64url-encoded WebAuthn credential ID
    CredentialData string // JSON-marshaled webauthn.Credential
    AAGUID         string
    CreatedAt      time.Time
}
```

### PasskeyChallenge struct

```go
type PasskeyChallenge struct {
    ID          string
    UserID      *string   // nil for authentication challenges; non-nil for registration
    SessionData string    // JSON-marshaled passkeyChallengeData{session_data, name}; written and read exclusively by PasskeyHandler
    ExpiresAt   time.Time
    CreatedAt   time.Time
}
```

## MagicLinkStore

```go
type MagicLinkStore interface {
    CreateMagicLink(ctx context.Context, email, tokenHash string, expiresAt time.Time) (*MagicLink, error)
    FindAndDeleteMagicLink(ctx context.Context, tokenHash string) (*MagicLink, error)
    DeleteExpiredMagicLinks(ctx context.Context) error
}
```

`FindAndDeleteMagicLink` atomically retrieves and removes the record matching `tokenHash`. Returns `auth.ErrNotFound` when not found. Only the SHA-256 hash of the raw token is persisted.

### MagicLink struct

```go
type MagicLink struct {
    ID        string
    Email     string
    TokenHash string
    ExpiresAt time.Time
    CreatedAt time.Time
}
```

## EmailVerificationStore

```go
type EmailVerificationStore interface {
    CreateEmailVerification(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error)
    ConsumeEmailVerification(ctx context.Context, tokenHash string) (*EmailVerificationToken, error)
    SetEmailVerified(ctx context.Context, userID string) error
}
```

`ConsumeEmailVerification` atomically looks up and deletes the token. Returns `auth.ErrNotFound` when not found.

### EmailVerificationToken struct

```go
type EmailVerificationToken struct {
    ID        string
    UserID    string
    TokenHash string
    ExpiresAt time.Time
    CreatedAt time.Time
}
```

## TOTPStore

```go
type TOTPStore interface {
    CreateTOTPSecret(ctx context.Context, userID, secret string) (*TOTPSecret, error)
    GetTOTPSecret(ctx context.Context, userID string) (*TOTPSecret, error)
    DeleteTOTPSecret(ctx context.Context, userID string) error
}
```

`GetTOTPSecret` returns `auth.ErrTOTPNotFound` when no secret is enrolled for the user. `CreateTOTPSecret` replaces any existing secret. The `Secret` field holds the unpadded base32-encoded TOTP secret.

### TOTPSecret struct

```go
type TOTPSecret struct {
    ID        string
    UserID    string
    Secret    string // base32-encoded secret; applications may store it encrypted
    CreatedAt time.Time
}
```

## PasswordResetStore

```go
type PasswordResetStore interface {
    CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
    FindPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
    DeletePasswordResetToken(ctx context.Context, id string) error
    DeleteExpiredPasswordResetTokens(ctx context.Context) error
}
```

### PasswordResetToken struct

```go
type PasswordResetToken struct {
    ID        string
    UserID    string
    TokenHash string
    ExpiresAt time.Time
    CreatedAt time.Time
}
```

`FindPasswordResetToken` returns `auth.ErrInvalidToken` when no matching record exists. Implementations may also return `auth.ErrExpiredToken` when a record is found but has already expired — `PasswordResetHandler.ResetPassword` treats both as a `400 Bad Request` with an `"invalid or expired reset token"` message. Expiry checking in the handler provides a second layer of validation, so returning `auth.ErrInvalidToken` for all failure cases is also acceptable. Only the SHA-256 hash of the raw token is stored. Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation.

## OIDCLinkNonceStore

```go
type OIDCLinkNonceStore interface {
    CreateLinkNonce(ctx context.Context, userID, nonceHash string, expiresAt time.Time) (*OIDCLinkNonce, error)
    ConsumeAndDeleteLinkNonce(ctx context.Context, nonceHash string) (*OIDCLinkNonce, error)
    DeleteExpiredLinkNonces(ctx context.Context) error
}
```

Required when using account linking with either `OIDCHandler` (`OIDCHandler.CreateLinkNonce` and `OIDCHandler.Link`) or `OAuth2Handler` (`OAuth2Handler.CreateLinkNonce` and `OAuth2Handler.Link`). When the respective handler's `LinkNonces` field is `nil`, both endpoints return HTTP 503 `"account linking not configured"`. Only the SHA-256 hash of the raw nonce is stored.

`ConsumeAndDeleteLinkNonce` must atomically retrieve and remove the record matching `nonceHash`. Return `auth.ErrNotFound` when no matching record exists. The returned record **may be expired**; callers are responsible for checking `ExpiresAt`. Schedule `DeleteExpiredLinkNonces` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation.

### OIDCLinkNonce struct

```go
type OIDCLinkNonce struct {
    ID        string
    UserID    string
    NonceHash string
    ExpiresAt time.Time
    CreatedAt time.Time
}
```

## RBACUserStore

```go
type RBACUserStore interface {
    GetRoles(ctx context.Context, userID string) ([]Role, error)
    AssignRole(ctx context.Context, userID string, role Role) error
    RevokeRole(ctx context.Context, userID string, role Role) error
}
```

Implement this interface to enable role-based access control. It is separate from `UserStore` and only required when you use `RequireRole` or `RequirePermission` middleware.
