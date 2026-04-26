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

!!! tip "Scheduling cleanup"
    Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation of expired tokens.
