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

## Behaviour

`SendVerification` silently skips already-verified addresses and returns the same success response whether or not the address is registered, preventing enumeration.

To gate login on email verification, set `RequireVerification: true` on `AuthHandler`.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `SendVerification` | 200 OK | Always (even if email is unregistered or already verified) |
| `SendVerification` | 400 Bad Request | Missing `email` field |
| `VerifyEmail` | 200 OK | `{"message": "email verified"}` |
| `VerifyEmail` | 400 Bad Request | Missing `token` query parameter; invalid or expired token |
| `VerifyEmail` | 500 Internal Server Error | Store failure when marking email as verified |

!!! info "Silent success for unregistered / already-verified addresses"
    `SendVerification` returns 200 for unregistered emails and already-verified addresses without storing a token or sending an email. Only the missing-`email` validation check surfaces as a non-200 error.
