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

`SendVerification` always returns HTTP 200:

```json
{"message": "if that address is registered, a verification email has been sent"}
```

`VerifyEmail` returns HTTP 200 on success:

```json
{"message": "email verified"}
```

It returns HTTP 400 for a missing or invalid/expired token.

To gate login on email verification, set `RequireVerification: true` on `AuthHandler`.
