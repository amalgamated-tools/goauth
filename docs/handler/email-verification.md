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

if err := h.Validate(); err != nil {
    log.Fatal(err)
}
```

`Validate()` returns an error if `Users`, `Verifications`, or `SendEmail` is `nil`, with a descriptive message such as `"EmailVerificationHandler misconfigured: SendEmail is required"` so the cause is immediately obvious in logs. Call it once at server startup so missing dependencies surface immediately rather than at the first request.

A nil `SendEmail` is caught by `Validate()` at startup. To skip email delivery in tests, supply a no-op `SendEmail` function instead.

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

`SendVerification` returns HTTP 400 for a missing `email` field or a malformed request body. Beyond the `400` case, it returns HTTP 200 regardless of whether the address is registered:

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
| `SendVerification` | 200 OK | Always, except for the 400 case (even if email is unregistered or already verified) |
| `SendVerification` | 400 Bad Request | Missing `email` field |
| `VerifyEmail` | 200 OK | `{"message": "email verified"}` |
| `VerifyEmail` | 400 Bad Request | Missing `token` query parameter; invalid or expired token |
| `VerifyEmail` | 500 Internal Server Error | Unexpected store failure when consuming the verification token or marking the email as verified |

!!! info "Silent success for unregistered / already-verified addresses"
    `SendVerification` returns 200 for unregistered emails and already-verified addresses without storing a token or sending an email. Only the missing-`email` validation check (400) surfaces as a non-200 error.

## Observability

`EmailVerificationHandler` emits structured log events via `slog.ErrorContext` before every HTTP 500 response and for non-fatal email delivery failures, propagating the request context for trace correlation.

| Event | Level | `slog` message | Endpoint |
|---|---|---|---|
| User lookup store failure | `ERROR` | `"failed to find user for email verification"` | `SendVerification` |
| Verification token generation failure | `ERROR` | `"failed to generate verification token"` | `SendVerification` |
| Token persistence store failure | `ERROR` | `"failed to store verification token"` | `SendVerification` |
| Email delivery failure | `ERROR` | `"failed to send verification email"` | `SendVerification` |
| Token consumption store failure | `ERROR` | `"failed to consume verification token"` | `VerifyEmail` |
| Email-verified flag persistence failure | `ERROR` | `"failed to mark email as verified"` | `VerifyEmail` |

The email delivery failure event is `ERROR`-level but the handler still returns HTTP 200 (see [Token retention on email delivery failure](#token-retention-on-email-delivery-failure)). The three `SendVerification` lookup/token events (`"failed to find user for email verification"`, `"failed to generate verification token"`, `"failed to store verification token"`) also return HTTP 200 — `SendVerification` always returns HTTP 200 to prevent email enumeration. Only the two `VerifyEmail` `ERROR`-level events are followed by an HTTP 500 response.
