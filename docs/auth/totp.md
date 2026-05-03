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

## Base32 encoding

All TOTP secrets are encoded with a specific base32 alphabet (standard RFC 4648 base32, no padding). Use `auth.TOTPEncoding()` when you need to encode or decode TOTP secrets outside of the built-in functions — this ensures consistency with the encoding used internally by `GenerateTOTPSecret`, `ValidateTOTP`, and `GenerateTOTPCode`.

```go
// Encode raw secret bytes to the TOTP base32 format.
encoded := auth.TOTPEncoding().EncodeToString(rawBytes)

// Decode a stored secret back to raw bytes (e.g. for custom HMAC use).
rawBytes, err := auth.TOTPEncoding().DecodeString(secret)
```

## HTTP handler

See [TOTPHandler](../handler/totp.md) for the ready-to-mount HTTP handler that wraps this logic.
