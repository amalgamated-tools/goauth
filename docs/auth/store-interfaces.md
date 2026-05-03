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

Return `auth.ErrEmailExists` from `CreateOIDCUser` when the given email is already registered. `OIDCHandler` relies on this to handle a race condition where two concurrent first-time OIDC logins for the same email both attempt to create an account simultaneously: when `CreateOIDCUser` returns `ErrEmailExists`, the handler retries by looking up the now-existing user instead.

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

Return `auth.ErrNotFound` from `FindSessionByID`, `FindSessionByRefreshTokenHash`, and `DeleteSession` when the record is not found. `FindSessionByID` may also return `auth.ErrSessionRevoked` when a session exists in a revoked state; the middleware treats both as a `401` response.

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

## MagicLinkStore

```go
type MagicLinkStore interface {
    CreateMagicLink(ctx context.Context, email, tokenHash string, expiresAt time.Time) (*MagicLink, error)
    FindAndDeleteMagicLink(ctx context.Context, tokenHash string) (*MagicLink, error)
    DeleteExpiredMagicLinks(ctx context.Context) error
}
```

`FindAndDeleteMagicLink` atomically retrieves and removes the record matching `tokenHash`. Returns `auth.ErrNotFound` when not found. Only the SHA-256 hash of the raw token is persisted.

## EmailVerificationStore

```go
type EmailVerificationStore interface {
    CreateEmailVerification(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error)
    ConsumeEmailVerification(ctx context.Context, tokenHash string) (*EmailVerificationToken, error)
    SetEmailVerified(ctx context.Context, userID string) error
}
```

`ConsumeEmailVerification` atomically looks up and deletes the token. Returns `auth.ErrNotFound` when not found.

## TOTPStore

```go
type TOTPStore interface {
    CreateTOTPSecret(ctx context.Context, userID, secret string) (*TOTPSecret, error)
    GetTOTPSecret(ctx context.Context, userID string) (*TOTPSecret, error)
    DeleteTOTPSecret(ctx context.Context, userID string) error
}
```

`GetTOTPSecret` returns `auth.ErrTOTPNotFound` when no secret is enrolled for the user. `CreateTOTPSecret` replaces any existing secret. The `Secret` field holds the unpadded base32-encoded TOTP secret.

## PasswordResetStore

```go
type PasswordResetStore interface {
    CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
    FindPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
    DeletePasswordResetToken(ctx context.Context, id string) error
    DeleteExpiredPasswordResetTokens(ctx context.Context) error
}
```

`FindPasswordResetToken` returns `auth.ErrInvalidToken` when no matching record exists. Implementations may also return `auth.ErrExpiredToken` when a record is found but has already expired — `PasswordResetHandler.ResetPassword` treats both as a `400 Bad Request` with an `"invalid or expired reset token"` message. Expiry checking in the handler provides a second layer of validation, so returning `auth.ErrInvalidToken` for all failure cases is also acceptable. Only the SHA-256 hash of the raw token is stored. Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation.

## RBACUserStore

```go
type RBACUserStore interface {
    GetRoles(ctx context.Context, userID string) ([]Role, error)
    AssignRole(ctx context.Context, userID string, role Role) error
    RevokeRole(ctx context.Context, userID string, role Role) error
}
```

Implement this interface to enable role-based access control. It is separate from `UserStore` and only required when you use `RequireRole` or `RequirePermission` middleware.
