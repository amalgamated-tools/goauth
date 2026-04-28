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
    `RequestReset` always returns HTTP 200 with the following response, regardless of whether the email is registered:

    ```json
    {"message": "if that email is registered, a reset link has been sent"}
    ```

!!! note "Token cleanup on email delivery failure"
    If `SendResetEmail` returns an error, `RequestReset` deletes the stored reset token to keep state consistent. The caller still receives the generic HTTP 200 success response; the failure is logged server-side via `slog.ErrorContext`.

!!! tip "Scheduling cleanup"
    Schedule `DeleteExpiredPasswordResetTokens` periodically (e.g. via `maintenance.StartCleanup`) to prevent unbounded accumulation of expired tokens.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `RequestReset` | 200 OK | `{"message": "if that email is registered, a reset link has been sent"}` (always, even if email is unregistered or account is OIDC-only) |
| `RequestReset` | 400 Bad Request | Missing `email` field |
| `RequestReset` | 429 Too Many Requests | Rate limit exceeded (only when `RateLimiter` is configured) |
| `RequestReset` | 500 Internal Server Error | Store failure during user lookup, token creation, or token generation |
| `ResetPassword` | 200 OK | `{"message": "password reset successfully"}` |
| `ResetPassword` | 400 Bad Request | Missing `token` or `newPassword`; password outside 8–72 bytes; invalid or expired token; OIDC-only account (no password set) |
| `ResetPassword` | 500 Internal Server Error | Internal failure during token lookup, user lookup, password hashing, or password update |
