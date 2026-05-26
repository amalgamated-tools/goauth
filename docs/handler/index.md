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
| [OAuth2Handler](oauth2.md) | Generic OAuth2 login (GitHub, Discord, Slack, …) |
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

### APIKeyDTO

Returned by `APIKeyHandler.List` (and by `Create`, which also includes the raw `key` field):

```go
type APIKeyDTO struct {
    ID         string     `json:"id"`
    Name       string     `json:"name"`
    KeyPrefix  string     `json:"key_prefix"`
    LastUsedAt *time.Time `json:"last_used_at"`
    CreatedAt  time.Time  `json:"created_at"`
}

// Convert a *auth.APIKey to an APIKeyDTO (useful in custom handlers or tests).
dto := handler.ToAPIKeyDTO(apiKey)
```

### SessionDTO

Returned by `SessionHandler.List`:

```go
type SessionDTO struct {
    ID        string    `json:"id"`
    UserAgent string    `json:"user_agent"`
    IPAddress string    `json:"ip_address"`
    ExpiresAt time.Time `json:"expires_at"`
    CreatedAt time.Time `json:"created_at"`
}

// Convert a *auth.Session to a SessionDTO (useful in custom handlers or tests).
dto := handler.ToSessionDTO(session)
```

### PasskeyCredentialDTO

Returned by `PasskeyHandler.FinishRegistration` (HTTP 201) and `ListCredentials` (HTTP 200):

```go
type PasskeyCredentialDTO struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    AAGUID    string    `json:"aaguid"`
    CreatedAt time.Time `json:"created_at"`
}

// Convert an auth.PasskeyCredential to a PasskeyCredentialDTO (useful in custom handlers or tests).
dto := handler.ToPasskeyCredentialDTO(credential)
```

### AuthResponse

Returned by `Signup`, `Login`, `RefreshToken`, `VerifyMagicLink`, and `PasskeyHandler.FinishAuthentication`:

```go
type AuthResponse struct {
    Token        string  `json:"token"`
    RefreshToken string  `json:"refresh_token,omitempty"` // omitted when Sessions is nil
    User         UserDTO `json:"user"`
}
```

## Error responses

All handlers return errors as JSON with the `Content-Type: application/json` header. The shape is always:

```json
{"error": "human-readable message"}
```

The HTTP status code reflects the error category:

| Status | Meaning |
|---|---|
| `400 Bad Request` | Missing or malformed request body / parameters |
| `401 Unauthorized` | Invalid, expired, or absent credentials |
| `403 Forbidden` | Authenticated but not authorised (e.g. signup disabled, unverified email) |
| `404 Not Found` | Requested resource does not exist |
| `409 Conflict` | Duplicate resource (e.g. email already registered) |
| `429 Too Many Requests` | Rate limit exceeded (see [Rate limiting](../auth/rate-limiting.md)) |
| `500 Internal Server Error` | Unexpected server-side failure |
| `503 Service Unavailable` | A required dependency is not configured (e.g. `SendEmail`, `Sender`, `SendResetEmail`, or `WebAuthn` is `nil`) |

## Observability

Every HTTP 500 response is preceded by a `slog.ErrorContext` call that records the underlying error with the request context, enabling trace correlation. `slog.WarnContext` is used for non-fatal degradations that do not affect the HTTP response (e.g. failing to update a credential counter or revoke a session on logout).

goauth never sets or replaces the global `slog` handler. Configure your own handler before starting the server to control log destination, format, and minimum level.

Each handler's documentation lists the specific `slog` messages it emits. ERROR log records generally include an `error` attribute set to the raw Go error value; the misconfiguration message `"issueTokens: Sessions is set but RefreshCookieName is empty — call Validate() at startup"` is an exception.

One additional `ERROR`-level event is shared across all handlers:

| Event | Level | `slog` message | Condition |
|---|---|---|---|
| JSON serialisation failure | `ERROR` | `"failed to encode JSON response"` | `json.Encoder.Encode` fails after response headers are already written |

This event fires from the internal `writeJSON` helper after `w.WriteHeader` has been called, so the HTTP status code is already committed when it occurs. It does not correspond to a distinct HTTP error status — it reflects an encoding or write failure, such as a JSON marshaling problem (for example, an unsupported value or a `MarshalJSON` error) or a response write failure (for example, the client disconnecting mid-response).
