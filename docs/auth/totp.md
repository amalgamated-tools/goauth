# TOTP / MFA

goauth provides TOTP (Time-Based One-Time Password) support compatible with any TOTP authenticator app (Google Authenticator, Authy, etc.).

## Generating and verifying codes

```go
// During enrollment – generate a secret and return a QR code URI.
secret, err := auth.GenerateTOTPSecret()
uri := auth.TOTPProvisioningURI(secret, user.Email, "MyApp")

// During verification – validate a 6-digit code.
// Uses a ±1 time-step window to tolerate clock skew (~30 s).
ok, err := auth.ValidateTOTP(secret, code)

// GenerateTOTPCode computes the expected code for a given time.
// Intended for testing and tooling; use ValidateTOTP in production.
generatedCode, err := auth.GenerateTOTPCode(secret, time.Now())
```

## Replay protection

`ValidateTOTP` alone does not prevent a valid code from being used twice within the ~90-second window. Use `auth.TOTPUsedCodeCache` (zero value is ready to use) in `TOTPHandler` to block replays:

```go
var usedCodes auth.TOTPUsedCodeCache // process-local; zero value ready to use

if usedCodes.WasUsed(userID, code) {
    // reject
}
// ... validate code ...
usedCodes.MarkUsed(userID, code)
```

!!! warning "Multi-instance deployments"
    `TOTPUsedCodeCache` is process-local. For multi-instance deployments, supplement with a shared external cache (e.g. Redis) to prevent replay attacks across instances.

## HTTP handler

See [TOTPHandler](../handler/totp.md) for the ready-to-mount HTTP handler that wraps this logic.
