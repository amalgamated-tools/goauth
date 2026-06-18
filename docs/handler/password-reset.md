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
    // Logger:      nil, // optional; when nil, slog.Default() is resolved at each log site
}

if err := h.Validate(); err != nil {
    log.Fatal(err)
}
```

`Validate()` returns an error if `Users`, `Resets`, or `SendResetEmail` is `nil`, with a descriptive message such as `"PasswordResetHandler misconfigured: SendResetEmail is required"` so the cause is immediately obvious in logs. Call it once at server startup so missing dependencies surface immediately rather than at the first request.

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

Password constraints: 8–72 bytes. A password shorter than 8 bytes returns `{"error": "password must be at least 8 bytes"}`; a password longer than 72 bytes returns `{"error": "password must be at most 72 bytes"}`.

## Behaviour

Reset tokens are consumed (deleted) after successful use.

!!! note "Legacy error codes from `FindPasswordResetToken`"
    `ResetPassword` accepts `auth.ErrExpiredToken` and `auth.ErrInvalidToken` in addition to `auth.ErrNotFound` from `FindPasswordResetToken`. All three result in HTTP 400 `"invalid or expired reset token"`. This backward-compatible handling prevents silent HTTP 500 regressions when upgrading store implementations that return these legacy sentinels.

!!! warning "SendResetEmail is required"
    A nil `SendResetEmail` is caught by `Validate()` at startup. Configure `SendResetEmail` before mounting this handler in production.

!!! info "Email enumeration prevention"
    For non-operational outcomes, `RequestReset` returns HTTP 200 with the following response regardless of whether the email is registered. This prevents clients from distinguishing registered from unregistered addresses based on the response body or status. Operational failures may still surface as non-200 responses such as HTTP 500.

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
| `RequestReset` | 200 OK | Normal success response when not rate-limited (even if email is unregistered or account is OIDC-only) |
| `RequestReset` | 400 Bad Request | Missing `email` field |
| `RequestReset` | 429 Too Many Requests | Rate limit exceeded (only when `RateLimiter` is configured) |
| `RequestReset` | 500 Internal Server Error | Store failure during user lookup, token creation, or token generation |
| `RequestReset` | 503 Service Unavailable | `SendResetEmail` is `nil` (not configured) |
| `ResetPassword` | 200 OK | `{"message": "password reset successfully"}` |
| `ResetPassword` | 400 Bad Request | Missing `token` or `newPassword`; password outside 8–72 bytes; invalid, expired, or unrecognised token (`ErrNotFound`, `ErrExpiredToken`, or `ErrInvalidToken` from store); OIDC-only account (no password set) |
| `ResetPassword` | 500 Internal Server Error | Internal failure during token lookup, user lookup, password hashing, or password update |

## Observability

`PasswordResetHandler` emits structured log events via `slog.ErrorContext` before every HTTP 500 response and for non-fatal failures, propagating the request context for trace correlation. All log output goes through the handler's `Logger` field; when `Logger` is `nil`, `slog.Default()` is used.

| Event | Level | `slog` message | Endpoint |
|---|---|---|---|
| User lookup store failure | `ERROR` | `"password reset: lookup user"` | `RequestReset` |
| Token generation failure | `ERROR` | `"password reset: generate token"` | `RequestReset` |
| Token persistence store failure | `ERROR` | `"password reset: store token"` | `RequestReset` |
| Email delivery failure | `ERROR` | `"password reset: send email"` | `RequestReset` |
| Token cleanup failure after email failure | `ERROR` | `"password reset: cleanup token after email failure"` | `RequestReset` |
| Token lookup store failure | `ERROR` | `"password reset: find token"` | `ResetPassword` |
| User lookup store failure | `ERROR` | `"password reset: lookup user"` | `ResetPassword` |
| Password hashing failure | `ERROR` | `"password reset: hash password"` | `ResetPassword` |
| Password update store failure | `ERROR` | `"password reset: update password"` | `ResetPassword` |
| Token consumption failure | `ERROR` | `"password reset: consume token"` | `ResetPassword` |

The email delivery failure event (`"password reset: send email"`) and the token cleanup failure event (`"password reset: cleanup token after email failure"`) are both `ERROR`-level but the handler still returns HTTP 200 (see [Token cleanup on email delivery failure](#token-cleanup-on-email-delivery-failure)). The token consumption failure event (`"password reset: consume token"`) is also `ERROR`-level but does not abort the response — the password has already been updated and HTTP 200 is returned. All other `ERROR`-level events are followed by an HTTP 500 response.
