# Middleware

goauth ships four middleware constructors that can be applied to any `net/http`-compatible router.

## Configuration

```go
cfg := auth.Config{
    CookieName:   "session",    // HttpOnly cookie name
    APIKeyPrefix: "myapp_",     // set to enable API key auth; omit to disable
    Sessions:     sessionStore, // optional; enables server-side session revocation
}
```

## Standard auth middleware

Require an authenticated user on a route group:

```go
r.Use(auth.Middleware(jwtMgr, cfg, apiKeyStore))
```

## Admin middleware

Require admin status (checked via `AdminChecker.IsAdmin`, cached 5 seconds per user):

```go
type AdminChecker interface {
    IsAdmin(ctx context.Context, userID string) (bool, error)
}
```

`auth.UserStore` satisfies `AdminChecker` directly. For RBAC-based setups, use `auth.NewAdminCheckerFromRoleChecker` to adapt a `RoleChecker` (see [RBAC](rbac.md)):

```go
// The second argument is an auth.AdminChecker; UserStore satisfies this interface.
r.Use(auth.AdminMiddleware(jwtMgr, userStore, cfg, apiKeyStore))

// Or adapt a RoleChecker (treats RoleAdmin as admin):
adminChecker := auth.NewAdminCheckerFromRoleChecker(roleChecker)
r.Use(auth.AdminMiddleware(jwtMgr, adminChecker, cfg, apiKeyStore))
```

The internal admin cache has a **4,096-entry FIFO size cap** and sweeps expired entries at most once per minute during writes. Oldest-inserted entries are evicted first when the cap is reached.

## Role / permission middleware

Require a specific role or permission on a route group (see [RBAC](rbac.md)):

```go
r.Use(auth.RequireRole(jwtMgr, roleChecker, cfg, apiKeyStore, auth.RoleEditor))
r.Use(auth.RequirePermission(jwtMgr, roleChecker, cfg, apiKeyStore, auth.PermWriteContent))
```

## Reading context values

```go
// Read the resolved user ID anywhere downstream.
userID := auth.UserIDFromContext(r.Context())

// ContextWithUserID injects a user ID into a context manually.
// Useful in tests or custom middleware that bypass the standard auth flow.
ctx := auth.ContextWithUserID(r.Context(), userID)

// Store/retrieve arbitrary roles in context for downstream handlers.
ctx = auth.ContextWithRoles(ctx, []auth.Role{auth.RoleAdmin})
roles := auth.RolesFromContext(ctx)
```

## Token sources

Tokens are accepted from the `Authorization: Bearer <token>` header or from the configured cookie. API keys are **only** accepted from the `Authorization` header.

`auth.ExtractToken(r, cookieName)` is an exported helper that performs the same extraction (Bearer header first, then cookie fallback). Use it in custom middleware or handlers that need to read the token without invoking the full middleware stack.

```go
token := auth.ExtractToken(r, "session")
```

### API key `last_used_at` update throttle

To reduce database write pressure on high-traffic deployments, the middleware calls `APIKeyStore.TouchAPIKeyLastUsed` at most once every **5 minutes** per key ID within a single process. The in-process state is stored in a plain `map` protected by a mutex and is not shared between processes.

Practical implications:

- The `last_used_at` value returned by `APIKeyHandler.List` lags behind real usage by up to 5 minutes.
- In multi-process deployments (e.g. horizontal scaling), the 5-minute window is tracked independently per process, so the lag may appear shorter than 5 minutes from an external observer's perspective.
- The throttle map is swept whenever it has at least 100 entries, removing entries whose last write was at least 5 minutes ago.

If your application requires precise `last_used_at` timestamps, implement `TouchAPIKeyLastUsed` as a no-op and maintain a separate high-frequency audit log outside the library's throttle window.

## Session revocation

When `Sessions` is set, the middleware validates the JWT `jti` claim against the store and rejects requests whose session has been revoked or expired server-side. It also rejects requests where the session's stored `UserID` does not match the `sub` claim in the JWT — this protects against session fixation scenarios where a session ID from one user is embedded in another user's token. API key requests bypass the session check.

## Observability

All four middleware functions — `Middleware`, `AdminMiddleware`, `RequireRole`, and `RequirePermission` — share the same authentication path and emit structured log events via the standard library's `log/slog` package, propagating the request context for trace correlation.

| Event | Level | `slog` message |
|---|---|---|
| Token absent from header and cookie | `INFO` | `"authentication required"` |
| `TouchAPIKeyLastUsed` store call fails | `WARN` | `"failed to touch API key last_used_at"` |
| Unexpected error from `resolveUser` | `ERROR` | `"failed to resolve user"` |
| Unexpected error from `FindSessionByID` | `ERROR` | `"failed to look up session"` |

`ErrInvalidToken` and `ErrExpiredToken` are **not** logged — they are treated as expected conditions and produce a `401` response with no log noise.

goauth never sets or replaces the global `slog` handler. Configure your own handler before starting the server to control log destination, format, and minimum level.

## Error responses

All middleware constructors return errors as JSON with `Content-Type: application/json`:

```json
{"error": "human-readable message"}
```

| Status | Condition |
|---|---|
| `401 Unauthorized` | Missing, invalid, or expired token; revoked session |
| `403 Forbidden` | Authenticated user lacks required admin status, role, or permission |
| `429 Too Many Requests` | Rate limit exceeded (rate-limiting middleware only) |
| `500 Internal Server Error` | Store lookup failure |

See [handler error responses](../handler/index.md#error-responses) for the same format used by all HTTP handlers.
