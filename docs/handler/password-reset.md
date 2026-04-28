# PasswordResetHandler — Password Reset

`PasswordResetHandler` provides email-based password reset. Only accounts with a password hash (not OIDC-only accounts) can use the reset flow.

## Configuration

```go
h := &handler.PasswordResetHandler{
    Users:          userStore,
    Resets:         passwordResetStore,
    SendResetEmail: func(ctx context.Context, toEmail, rawToken string) error { /* send email */ return nil },
    TokenTTL:       time.Hour, // defaults to 1 hour
    RateLimiter:    rl,        // optional; recommended to limit abuse
}
```

## Routes

```
POST /password-reset/request   → h.RequestReset    // send reset email
POST /password-reset/confirm   → h.ResetPassword   // validate token and set new password
```

## Request bodies

`RequestReset`:
```json
{"email": "user@example.com"}
```

`ResetPassword`:
```json
{"token": "<raw-token>", "newPassword": "newpassword123"}
```

Password constraints: 8–72 bytes.

## Behaviour

Reset tokens are consumed (deleted) after successful use.

!!! info "Email enumeration prevention"
    `RequestReset` always returns HTTP 200 with a generic message, regardless of whether the email is registered.

!!! note "Token cleanup on email delivery failure"
    If `SendResetEmail` returns an error, `RequestReset` deletes the stored reset token to keep state consistent. The caller still receives the generic HTTP 200 success response; the failure is logged server-side via `slog.ErrorContext`.

!!! tip "Scheduling cleanup"
    Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation of expired tokens.

## HTTP status codes

### `RequestReset`

`RequestReset` returns HTTP 200 when the request passes rate limiting and validation (non-empty `email`, valid JSON), regardless of whether the address is registered, to prevent email enumeration.

| Status | Condition |
|---|---|
| **200 OK** | Success (generic message; address may or may not be registered) |
| 400 Bad Request | Missing or malformed request body; `email` field is empty |
| 429 Too Many Requests | Rate limit exceeded (when `RateLimiter` is set) |
| 500 Internal Server Error | Token generation failure (`GenerateRandomBase64`) or store failure (non-ErrNotFound error from `FindByEmail` or `CreatePasswordResetToken`) |

Success response body:
```json
{"message": "if that email is registered, a reset link has been sent"}
```

### `ResetPassword`

| Status | Condition |
|---|---|
| **200 OK** | Password updated successfully |
| 400 Bad Request | Missing or malformed request body; `token` is empty or invalid/expired; password fails validation |
| 500 Internal Server Error | Store failure (`FindPasswordResetToken`, `FindByID`, or `UpdatePassword`) |

Success response body:
```json
{"message": "password reset successfully"}
```
