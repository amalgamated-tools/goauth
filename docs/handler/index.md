# `handler` package

The `handler` package provides ready-to-mount HTTP handlers for every goauth authentication flow. All handlers use `net/http` only and are compatible with any router. Router-specific helpers (e.g. URL parameter extraction) are injected via a `func(r *http.Request, key string) string` field.

## Import path

```go
import "github.com/amalgamated-tools/goauth/handler"
```

## Available handlers

| Handler | Purpose |
|---|---|
| [AuthHandler](auth.md) | Email/password signup, login, logout, refresh tokens, profile |
| [OIDCHandler](oidc.md) | SSO / OpenID Connect login and account linking |
| [APIKeyHandler](api-keys.md) | API key creation, listing, and deletion |
| [SessionHandler](sessions.md) | Server-side session listing and revocation |
| [PasskeyHandler](passkeys.md) | WebAuthn passkey registration and authentication |
| [TOTPHandler](totp.md) | TOTP/MFA enrollment, verification, and management |
| [MagicLinkHandler](magic-links.md) | Passwordless login via one-time email links |
| [EmailVerificationHandler](email-verification.md) | Email address verification flow |
| [PasswordResetHandler](password-reset.md) | Email-based password reset |

## Shared response types

### UserDTO

Returned by `Me`, `UpdateProfile`, and embedded in `AuthResponse`:

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

### AuthResponse

Returned by `Signup`, `Login`, `RefreshToken`, and `VerifyMagicLink`:

```go
// Contains: token, refresh_token (when Sessions is set), and user (UserDTO)
```
