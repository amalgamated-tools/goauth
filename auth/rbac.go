package auth

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Role is a named set of permissions assigned to a user.
type Role string

// Permission is a single capability that can be granted to a role.
type Permission string

// Built-in roles.
const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// Built-in permissions.
const (
	PermManageUsers  Permission = "manage_users"
	PermReadContent  Permission = "read_content"
	PermWriteContent Permission = "write_content"
)

var (
	rolePermMu       sync.RWMutex
	defaultRolePerms = map[Role][]Permission{
		RoleAdmin:  {PermManageUsers, PermReadContent, PermWriteContent},
		RoleEditor: {PermReadContent, PermWriteContent},
		RoleViewer: {PermReadContent},
	}
	rolePermissions = copyRolePerms(defaultRolePerms)
)

func copyRolePerms(src map[Role][]Permission) map[Role][]Permission {
	dst := make(map[Role][]Permission, len(src))
	for k, v := range src {
		perms := make([]Permission, len(v))
		copy(perms, v)
		dst[k] = perms
	}
	return dst
}

// RegisterRolePermissions adds or replaces the permission set for a role.
// This is intended for application startup; it is safe for concurrent use.
func RegisterRolePermissions(role Role, perms []Permission) {
	rolePermMu.Lock()
	defer rolePermMu.Unlock()
	cp := make([]Permission, len(perms))
	copy(cp, perms)
	rolePermissions[role] = cp
}

// RoleChecker determines whether a user has a given role or permission.
// Implementations must be safe for concurrent use.
type RoleChecker interface {
	HasRole(ctx context.Context, userID string, role Role) (bool, error)
	HasPermission(ctx context.Context, userID string, perm Permission) (bool, error)
}

// RBACUserStore is the optional store interface consumers implement to enable
// RBAC. It is entirely separate from UserStore; implement only when you want
// role-based access control.
type RBACUserStore interface {
	GetRoles(ctx context.Context, userID string) ([]Role, error)
	AssignRole(ctx context.Context, userID string, role Role) error
	RevokeRole(ctx context.Context, userID string, role Role) error
}

// StoreRoleChecker implements RoleChecker by delegating to an RBACUserStore.
type StoreRoleChecker struct {
	store RBACUserStore
}

// NewStoreRoleChecker returns a RoleChecker backed by store.
func NewStoreRoleChecker(store RBACUserStore) *StoreRoleChecker {
	return &StoreRoleChecker{store: store}
}

// HasRole reports whether the user has been assigned role.
func (s *StoreRoleChecker) HasRole(ctx context.Context, userID string, role Role) (bool, error) {
	roles, err := s.store.GetRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("get roles: %w", err)
	}
	if slices.Contains(roles, role) {
		return true, nil
	}
	return false, nil
}

// HasPermission reports whether any role assigned to the user grants perm.
func (s *StoreRoleChecker) HasPermission(ctx context.Context, userID string, perm Permission) (bool, error) {
	roles, err := s.store.GetRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("get roles: %w", err)
	}
	rolePermMu.RLock()
	defer rolePermMu.RUnlock()
	for _, role := range roles {
		if slices.Contains(rolePermissions[role], perm) {
			return true, nil
		}
	}
	return false, nil
}

const (
	cacheSweepInterval         = time.Minute
	defaultRoleCacheMaxEntries = 4096
	defaultPermCacheMaxEntries = 4096
)

// cachingRoleChecker wraps a RoleChecker and caches results for ttl.
type cachingRoleChecker struct {
	delegate RoleChecker
	ttl      time.Duration

	roleMu            sync.RWMutex
	roleEntries       map[roleCacheKey]roleCacheEntry
	roleLastSweepTime time.Time

	permMu            sync.RWMutex
	permEntries       map[permCacheKey]permCacheEntry
	permLastSweepTime time.Time
}

type roleCacheKey struct {
	userID string
	role   Role
}

type roleCacheEntry struct {
	result    bool
	expiresAt time.Time
}

type permCacheKey struct {
	userID string
	perm   Permission
}

type permCacheEntry struct {
	result    bool
	expiresAt time.Time
}

// NewCachingRoleChecker wraps delegate and caches HasRole/HasPermission results
// for ttl. If ttl <= 0, defaultMiddlewareCacheTTL is used.
func NewCachingRoleChecker(delegate RoleChecker, ttl time.Duration) RoleChecker {
	if ttl <= 0 {
		ttl = defaultMiddlewareCacheTTL
	}
	return &cachingRoleChecker{
		delegate:    delegate,
		ttl:         ttl,
		roleEntries: make(map[roleCacheKey]roleCacheEntry),
		permEntries: make(map[permCacheKey]permCacheEntry),
	}
}

func (c *cachingRoleChecker) sweepRoleEntriesLocked(now time.Time) {
	if now.Sub(c.roleLastSweepTime) >= cacheSweepInterval {
		c.roleLastSweepTime = now
		for k, e := range c.roleEntries {
			if !e.expiresAt.After(now) {
				delete(c.roleEntries, k)
			}
		}
	}
	for len(c.roleEntries) >= defaultRoleCacheMaxEntries {
		for k := range c.roleEntries {
			delete(c.roleEntries, k)
			break
		}
	}
}

func (c *cachingRoleChecker) sweepPermEntriesLocked(now time.Time) {
	if now.Sub(c.permLastSweepTime) >= cacheSweepInterval {
		c.permLastSweepTime = now
		for k, e := range c.permEntries {
			if !e.expiresAt.After(now) {
				delete(c.permEntries, k)
			}
		}
	}
	for len(c.permEntries) >= defaultPermCacheMaxEntries {
		for k := range c.permEntries {
			delete(c.permEntries, k)
			break
		}
	}
}

func (c *cachingRoleChecker) HasRole(ctx context.Context, userID string, role Role) (bool, error) {
	key := roleCacheKey{userID: userID, role: role}
	now := time.Now()

	c.roleMu.RLock()
	entry, ok := c.roleEntries[key]
	c.roleMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.result, nil
	}

	result, err := c.delegate.HasRole(ctx, userID, role)
	if err != nil {
		return false, err
	}

	c.roleMu.Lock()
	c.sweepRoleEntriesLocked(now)
	c.roleEntries[key] = roleCacheEntry{result: result, expiresAt: now.Add(c.ttl)}
	c.roleMu.Unlock()
	return result, nil
}

func (c *cachingRoleChecker) HasPermission(ctx context.Context, userID string, perm Permission) (bool, error) {
	key := permCacheKey{userID: userID, perm: perm}
	now := time.Now()

	c.permMu.RLock()
	entry, ok := c.permEntries[key]
	c.permMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.result, nil
	}

	result, err := c.delegate.HasPermission(ctx, userID, perm)
	if err != nil {
		return false, err
	}

	c.permMu.Lock()
	c.sweepPermEntriesLocked(now)
	c.permEntries[key] = permCacheEntry{result: result, expiresAt: now.Add(c.ttl)}
	c.permMu.Unlock()
	return result, nil
}
