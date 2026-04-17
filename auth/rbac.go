package auth

import (
	"context"
	"fmt"
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
	for _, r := range roles {
		if r == role {
			return true, nil
		}
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
		for _, p := range rolePermissions[role] {
			if p == perm {
				return true, nil
			}
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
	roleOrder         []roleOrderEntry // insertion-order queue for FIFO eviction
	roleSeq           uint64
	roleLastSweepTime time.Time

	permMu            sync.RWMutex
	permEntries       map[permCacheKey]permCacheEntry
	permOrder         []permOrderEntry // insertion-order queue for FIFO eviction
	permSeq           uint64
	permLastSweepTime time.Time
}

type roleCacheKey struct {
	userID string
	role   Role
}

type roleCacheEntry struct {
	result    bool
	expiresAt time.Time
	seq       uint64 // matches the corresponding roleOrderEntry.seq
}

// roleOrderEntry tracks insertion order for FIFO eviction.
type roleOrderEntry struct {
	key roleCacheKey
	seq uint64
}

type permCacheKey struct {
	userID string
	perm   Permission
}

type permCacheEntry struct {
	result    bool
	expiresAt time.Time
	seq       uint64 // matches the corresponding permOrderEntry.seq
}

// permOrderEntry tracks insertion order for FIFO eviction.
type permOrderEntry struct {
	key permCacheKey
	seq uint64
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
		// Compact the order slice: discard entries whose map entry no longer
		// exists or has been superseded by a later insertion (seq mismatch).
		n := 0
		for _, o := range c.roleOrder {
			if e, ok := c.roleEntries[o.key]; ok && e.seq == o.seq {
				c.roleOrder[n] = o
				n++
			}
		}
		c.roleOrder = c.roleOrder[:n]
	}
	// Evict the oldest-inserted entries first until the cache is under capacity.
	for len(c.roleEntries) >= defaultRoleCacheMaxEntries {
		if len(c.roleOrder) == 0 {
			break
		}
		oldest := c.roleOrder[0]
		c.roleOrder = c.roleOrder[1:]
		if e, ok := c.roleEntries[oldest.key]; ok && e.seq == oldest.seq {
			delete(c.roleEntries, oldest.key)
		}
		// If seq mismatches, the slot is stale (entry was already evicted or
		// re-inserted with a newer seq); keep looping to find the real oldest.
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
		// Compact the order slice: discard stale entries.
		n := 0
		for _, o := range c.permOrder {
			if e, ok := c.permEntries[o.key]; ok && e.seq == o.seq {
				c.permOrder[n] = o
				n++
			}
		}
		c.permOrder = c.permOrder[:n]
	}
	// Evict the oldest-inserted entries first until the cache is under capacity.
	for len(c.permEntries) >= defaultPermCacheMaxEntries {
		if len(c.permOrder) == 0 {
			break
		}
		oldest := c.permOrder[0]
		c.permOrder = c.permOrder[1:]
		if e, ok := c.permEntries[oldest.key]; ok && e.seq == oldest.seq {
			delete(c.permEntries, oldest.key)
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
	c.roleSeq++
	c.roleEntries[key] = roleCacheEntry{result: result, expiresAt: now.Add(c.ttl), seq: c.roleSeq}
	c.roleOrder = append(c.roleOrder, roleOrderEntry{key: key, seq: c.roleSeq})
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
	c.permSeq++
	c.permEntries[key] = permCacheEntry{result: result, expiresAt: now.Add(c.ttl), seq: c.permSeq}
	c.permOrder = append(c.permOrder, permOrderEntry{key: key, seq: c.permSeq})
	c.permMu.Unlock()
	return result, nil
}
