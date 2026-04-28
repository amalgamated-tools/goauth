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

When `SendEmail` is `nil`, verification tokens are still created and stored but no email is delivered. This is useful in testing environments where email delivery is not required.

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

| Endpoint | Success | Notable error codes |
|---|---|---|
| `SendVerification` | 200 OK | 400 (email required) |
| `VerifyEmail` | 200 OK | 400 (token required or invalid/expired token) |

`SendVerification` always returns 200 whether or not the address is registered or already verified — this prevents email enumeration.
