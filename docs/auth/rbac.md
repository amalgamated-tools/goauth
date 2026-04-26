# RBAC (Role-Based Access Control)

goauth ships a lightweight RBAC layer built on top of `RBACUserStore`. Three built-in roles are pre-configured with default permissions; applications can override or extend them.

## Built-in roles and permissions

| Role | Permissions |
|---|---|
| `auth.RoleAdmin` | `auth.PermManageUsers`, `auth.PermReadContent`, `auth.PermWriteContent` |
| `auth.RoleEditor` | `auth.PermReadContent`, `auth.PermWriteContent` |
| `auth.RoleViewer` | `auth.PermReadContent` |

## Usage

```go
// Extend or override role permissions at startup.
auth.RegisterRolePermissions(auth.RoleAdmin, []auth.Permission{
    auth.PermManageUsers,
    auth.PermReadContent,
    auth.PermWriteContent,
    "billing:read", // custom permission
})

// Build a checker backed by your store.
checker := auth.NewStoreRoleChecker(rbacStore) // rbacStore implements auth.RBACUserStore

// Wrap with an in-process cache (recommended for hot paths).
cached := auth.NewCachingRoleChecker(checker, 30*time.Second)

// Use in handlers.
ok, err := cached.HasRole(ctx, userID, auth.RoleAdmin)
ok, err = cached.HasPermission(ctx, userID, auth.PermWriteContent)

// Adapt a RoleChecker to satisfy AdminChecker (for use with AdminMiddleware).
adminChecker := auth.NewAdminCheckerFromRoleChecker(cached)
```

## Store interface

The `RBACUserStore` interface is separate from `UserStore` and only required when using `RequireRole` or `RequirePermission` middleware:

```go
type RBACUserStore interface {
    GetRoles(ctx context.Context, userID string) ([]Role, error)
    AssignRole(ctx context.Context, userID string, role Role) error
    RevokeRole(ctx context.Context, userID string, role Role) error
}
```

See [Store Interfaces](store-interfaces.md#rbacuserstore) for full details.
