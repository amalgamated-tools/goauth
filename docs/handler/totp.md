# TOTPHandler — TOTP / MFA

`TOTPHandler` provides HTTP endpoints for enrolling and managing TOTP (Time-Based One-Time Passwords).

## Configuration

```go
h := &handler.TOTPHandler{
    TOTP:      totpStore,
    Users:     userStore,
    Issuer:    "MyApp",
    UsedCodes: &auth.TOTPUsedCodeCache{}, // required; pointer to zero value; prevents replay attacks
}
```

## Routes

All routes require auth middleware.

```
POST   /totp/generate   → h.Generate   // generate secret + provisioning URI (not persisted)
POST   /totp/enroll     → h.Enroll     // verify first code and persist the secret
POST   /totp/verify     → h.Verify     // verify a code against the enrolled secret
GET    /totp/status     → h.Status     // check whether TOTP is enrolled
DELETE /totp            → h.Disable    // remove enrolled secret (204 No Content)
```

## Enrollment flow

Enrollment is a two-step flow:

1. `Generate` returns a secret and `otpauth://` URI for the QR code.
2. `Enroll` verifies the first code from the authenticator app and persists the secret.

## Response types

| Route | HTTP status | Response body |
|---|---|---|
| `Generate` | 200 | `{"secret": "...", "provisioning_uri": "otpauth://..."}` — `Cache-Control: no-store` |
| `Enroll` | 200 | `{"enrolled": true}` |
| `Verify` | 200 | `{"valid": true}` |
| `Status` | 200 | `{"enrolled": <bool>}` |
| `Disable` | 204 | *(no body)* |

See [TOTP / MFA](../auth/totp.md) for the underlying primitives and replay protection details.
