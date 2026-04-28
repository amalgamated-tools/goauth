# EmailVerificationHandler — Email Verification

`EmailVerificationHandler` handles the email address verification flow: send a verification email and process the verification link.

## Configuration

```go
h := &handler.EmailVerificationHandler{
    Users:         userStore,
    Verifications: verificationStore,
    SendEmail:     func(ctx context.Context, to, token string) error { /* send email */ return nil },
    TokenTTL:      24 * time.Hour, // defaults to 24 hours
}
```

When `SendEmail` is `nil`, `SendVerification` returns HTTP 503 before any database write — treat a missing sender as a misconfiguration error. To skip email delivery in tests, supply a no-op `SendEmail` function instead.

!!! note "Token retention on email delivery failure"
    If `SendEmail` is non-nil but returns an error, `SendVerification` logs the failure server-side and returns HTTP 200 — the stored token is **not** deleted. The user can re-request verification and the token will expire naturally after 24 hours (or the configured `TokenTTL`). This differs from `PasswordResetHandler`, which deletes the reset token when email delivery fails.

## Routes

```
POST /verify-email/send   → h.SendVerification   // send verification email
GET  /verify-email        → h.VerifyEmail         // ?token=<token> → marks email verified
```

## Response types

| Endpoint | HTTP status | Response body |
|---|---|---|
| `SendVerification` | 200 OK | `{"message": "if that address is registered, a verification email has been sent"}` |
| `VerifyEmail` | 200 OK | `{"message": "email verified"}` |

## Behaviour

`SendVerification` silently skips already-verified addresses and returns the same success response whether or not the address is registered, preventing enumeration.

`SendVerification` returns HTTP 400 for a missing `email` field or a malformed request body. For all valid requests it returns HTTP 200 regardless of whether the address is registered:

```json
{"message": "if that address is registered, a verification email has been sent"}
```

`VerifyEmail` returns HTTP 200 on success:

```json
{"message": "email verified"}
```

It returns HTTP 400 for a missing or invalid/expired token, and HTTP 500 when a store operation fails (`ConsumeEmailVerification` or `SetEmailVerified` returns an unexpected error). Error responses use the shape `{"error": "..."}`.

To gate login on email verification, set `RequireVerification: true` on `AuthHandler`.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `SendVerification` | 200 OK | Always (even if email is unregistered or already verified) |
| `SendVerification` | 400 Bad Request | Missing `email` field |
| `SendVerification` | 503 Service Unavailable | `SendEmail` is `nil` (not configured) |
| `VerifyEmail` | 200 OK | `{"message": "email verified"}` |
| `VerifyEmail` | 400 Bad Request | Missing `token` query parameter; invalid or expired token |
| `VerifyEmail` | 500 Internal Server Error | Unexpected store failure when consuming the verification token or marking the email as verified |

!!! info "Silent success for unregistered / already-verified addresses"
    `SendVerification` returns 200 for unregistered emails and already-verified addresses without storing a token or sending an email. Only the missing-`email` validation check surfaces as a non-200 error.
