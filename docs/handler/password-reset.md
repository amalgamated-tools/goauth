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

## Behaviour

`RequestReset` returns the same success response whether or not the email is registered, preventing enumeration. Reset tokens are consumed (deleted) after successful use.

!!! info "Email enumeration prevention"
    `RequestReset` always returns HTTP 200 with a generic message, regardless of whether the email is registered.

!!! note "Token cleanup on email delivery failure"
    If `SendResetEmail` returns an error, `RequestReset` deletes the stored reset token to keep state consistent. The caller still receives the generic HTTP 200 success response; the failure is logged server-side via `slog.ErrorContext`.

!!! tip "Scheduling cleanup"
    Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation of expired tokens.

## HTTP status codes

| Endpoint | Success | Notable error codes |
|---|---|---|
| `RequestReset` | 200 OK | 400 (email required), 429 (rate limited) |
| `ResetPassword` | 200 OK | 400 (token or new password required, invalid/expired token, or weak password) |

`RequestReset` always returns 200 whether or not the email is registered, preventing enumeration.
