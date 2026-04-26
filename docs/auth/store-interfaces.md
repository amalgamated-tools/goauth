# Store Interfaces

The library defines store interfaces that consuming applications implement against their own database. Return `auth.ErrNotFound` (or wrap it) when a record is not found — handlers check for this sentinel to produce correct HTTP status codes.

## UserStore

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

Return `auth.ErrEmailExists` from `CreateUser` when a duplicate email is detected.

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
    CreateAPIKey(ctx, userID, name, keyHash, keyPrefix string) (*APIKey, error)
    ListAPIKeysByUser(ctx, userID string) ([]APIKey, error)
    FindAPIKeyByIDAndUser(ctx, id, userID string) (*APIKey, error)
    ValidateAPIKey(ctx, keyHash string) (userID, apiKeyID string, err error)
    TouchAPIKeyLastUsed(ctx, id string) error
    DeleteAPIKey(ctx, id, userID string) error
}
```

`ValidateAPIKey` is given the SHA-256 hex hash of the raw key. Store only the hash — never the plaintext key.

## SessionStore

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

## PasskeyStore

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

## MagicLinkStore

```go
type MagicLinkStore interface {
    CreateMagicLink(ctx, email, tokenHash string, expiresAt time.Time) (*MagicLink, error)
    FindAndDeleteMagicLink(ctx, tokenHash string) (*MagicLink, error)
    DeleteExpiredMagicLinks(ctx) error
}
```

`FindAndDeleteMagicLink` atomically retrieves and removes the record matching `tokenHash`. Returns `auth.ErrNotFound` when not found. Only the SHA-256 hash of the raw token is persisted.

## EmailVerificationStore

```go
type EmailVerificationStore interface {
    CreateEmailVerification(ctx, userID, tokenHash string, expiresAt time.Time) (*EmailVerificationToken, error)
    ConsumeEmailVerification(ctx, tokenHash string) (*EmailVerificationToken, error)
    SetEmailVerified(ctx, userID string) error
}
```

`ConsumeEmailVerification` atomically looks up and deletes the token. Returns `auth.ErrNotFound` when not found.

## TOTPStore

```go
type TOTPStore interface {
    CreateTOTPSecret(ctx, userID, secret string) (*TOTPSecret, error)
    GetTOTPSecret(ctx, userID string) (*TOTPSecret, error)
    DeleteTOTPSecret(ctx, userID string) error
}
```

`GetTOTPSecret` returns `auth.ErrTOTPNotFound` when no secret is enrolled for the user. `CreateTOTPSecret` replaces any existing secret. The `Secret` field holds the unpadded base32-encoded TOTP secret.

## PasswordResetStore

```go
type PasswordResetStore interface {
    CreatePasswordResetToken(ctx, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
    FindPasswordResetToken(ctx, tokenHash string) (*PasswordResetToken, error)
    DeletePasswordResetToken(ctx, id string) error
    DeleteExpiredPasswordResetTokens(ctx) error
}
```

`FindPasswordResetToken` returns `auth.ErrInvalidToken` when no matching record exists. Only the SHA-256 hash of the raw token is stored. Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation.

## RBACUserStore

```go
type RBACUserStore interface {
    GetRoles(ctx context.Context, userID string) ([]Role, error)
    AssignRole(ctx context.Context, userID string, role Role) error
    RevokeRole(ctx context.Context, userID string, role Role) error
}
```

Implement this interface to enable role-based access control. It is separate from `UserStore` and only required when you use `RequireRole` or `RequirePermission` middleware.
