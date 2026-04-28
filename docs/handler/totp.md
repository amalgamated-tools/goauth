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

| Route | HTTP status | Response body | Notable error codes |
|---|---|---|---|
| `Generate` | 200 | `{"secret": "...", "provisioning_uri": "otpauth://..."}` — `Cache-Control: no-store`, `Pragma: no-cache` | — |
| `Enroll` | 200 | `{"enrolled": true}` | 400 (missing fields or invalid secret), 401 (invalid TOTP code) |
| `Verify` | 200 | `{"valid": true}` | 400 (code required), 401 (invalid code), 404 (TOTP not configured) |
| `Status` | 200 | `{"enrolled": <bool>}` | — |
| `Disable` | 204 | *(no body)* | 404 (TOTP not configured) |

See [TOTP / MFA](../auth/totp.md) for the underlying primitives and replay protection details.

## HTTP status codes

| Endpoint | Status | Condition |
|---|---|---|
| `Generate` | 200 OK | Success |
| `Generate` | 500 Internal Server Error | Failed to generate secret or look up user |
| `Enroll` | 200 | Success; `{"enrolled": true}` |
| `Enroll` | 400 Bad Request | Missing `secret` or `code`; invalid base32 `secret` (< 20 bytes) |
| `Enroll` | 401 Unauthorized | Invalid or replayed TOTP code |
| `Enroll` | 500 Internal Server Error | Store failure |
| `Verify` | 200 OK | Success; `{"valid": true}` |
| `Verify` | 400 Bad Request | Missing `code` |
| `Verify` | 401 Unauthorized | Invalid or replayed TOTP code |
| `Verify` | 404 Not Found | TOTP not configured for the user |
| `Verify` | 500 Internal Server Error | Store failure |
| `Status` | 200 OK | Success |
| `Status` | 500 Internal Server Error | Store failure (non-`ErrTOTPNotFound` error) |
| `Disable` | 204 No Content | Success |
| `Disable` | 404 Not Found | TOTP not configured for the user |
| `Disable` | 500 Internal Server Error | Store failure |
