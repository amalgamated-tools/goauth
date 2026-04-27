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
// The second argument is an auth.AdminChecker; UserStore satisfies this interface.
r.Use(auth.AdminMiddleware(jwtMgr, userStore, cfg, apiKeyStore))
```

`AdminChecker` is a single-method interface:

```go
type AdminChecker interface {
    IsAdmin(ctx context.Context, userID string) (bool, error)
}
```

`auth.UserStore` satisfies `AdminChecker` directly. To derive an `AdminChecker` from a `RoleChecker`, use `auth.NewAdminCheckerFromRoleChecker` (see [RBAC](rbac.md)).

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

## Session revocation

When `Sessions` is set, the middleware validates the JWT `jti` claim against the store and rejects requests whose session has been revoked or expired server-side. API key requests bypass the session check.
