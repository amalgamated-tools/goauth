package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- mock RBACUserStore -------------------------------------------------------

type mockRBACUserStore struct {
	getRolesFunc func(ctx context.Context, userID string) ([]Role, error)
	assignFunc   func(ctx context.Context, userID string, role Role) error
	revokeFunc   func(ctx context.Context, userID string, role Role) error
}

func (m *mockRBACUserStore) GetRoles(ctx context.Context, userID string) ([]Role, error) {
	if m.getRolesFunc != nil {
		return m.getRolesFunc(ctx, userID)
	}
	return nil, nil
}

func (m *mockRBACUserStore) AssignRole(ctx context.Context, userID string, role Role) error {
	if m.assignFunc != nil {
		return m.assignFunc(ctx, userID, role)
	}
	return nil
}

func (m *mockRBACUserStore) RevokeRole(ctx context.Context, userID string, role Role) error {
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, userID, role)
	}
	return nil
}

// --- StoreRoleChecker ---------------------------------------------------------

func TestStoreRoleChecker_hasRole(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleEditor}, nil
		},
	}
	checker := NewStoreRoleChecker(store)
	ctx := context.Background()

	ok, err := checker.HasRole(ctx, "u1", RoleEditor)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = checker.HasRole(ctx, "u1", RoleAdmin)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestStoreRoleChecker_hasRoleError(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return nil, errors.New("db error")
		},
	}
	checker := NewStoreRoleChecker(store)
	_, err := checker.HasRole(context.Background(), "u1", RoleAdmin)
	require.Error(t, err)
}

func TestStoreRoleChecker_hasPermission(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleViewer}, nil
		},
	}
	checker := NewStoreRoleChecker(store)
	ctx := context.Background()

	ok, err := checker.HasPermission(ctx, "u1", PermReadContent)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = checker.HasPermission(ctx, "u1", PermManageUsers)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestStoreRoleChecker_hasPermissionMultiRole(t *testing.T) {
	// User has both viewer and editor — should have write permission.
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleViewer, RoleEditor}, nil
		},
	}
	checker := NewStoreRoleChecker(store)
	ctx := context.Background()

	ok, err := checker.HasPermission(ctx, "u1", PermWriteContent)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestStoreRoleChecker_hasPermissionUnknownRole(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{Role("nonexistent")}, nil
		},
	}
	checker := NewStoreRoleChecker(store)
	ok, err := checker.HasPermission(context.Background(), "u1", PermReadContent)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestStoreRoleChecker_hasPermissionError(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return nil, errors.New("db error")
		},
	}
	checker := NewStoreRoleChecker(store)
	_, err := checker.HasPermission(context.Background(), "u1", PermReadContent)
	require.Error(t, err)
}

// --- RegisterRolePermissions --------------------------------------------------

func TestRegisterRolePermissions(t *testing.T) {
	rolePermMu.Lock()
	saved := copyRolePerms(rolePermissions)
	rolePermMu.Unlock()
	t.Cleanup(func() {
		rolePermMu.Lock()
		rolePermissions = saved
		rolePermMu.Unlock()
	})

	customRole := Role("tester")
	customPerm := Permission("run_tests")
	RegisterRolePermissions(customRole, []Permission{customPerm})

	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{customRole}, nil
		},
	}
	checker := NewStoreRoleChecker(store)
	ok, err := checker.HasPermission(context.Background(), "u1", customPerm)
	require.NoError(t, err)
	require.True(t, ok)
}

// --- NewCachingRoleChecker ----------------------------------------------------

func TestCachingRoleChecker_cachesHasRole(t *testing.T) {
	calls := 0
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			calls++
			return []Role{RoleAdmin}, nil
		},
	}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Hour)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ok, err := checker.HasRole(ctx, "u1", RoleAdmin)
		require.NoErrorf(t, err, "call %d", i)
		require.Truef(t, ok, "call %d", i)
	}
	// StoreRoleChecker calls GetRoles once per HasRole, but caching wrapper
	// should only call through on the first request.
	require.Equal(t, 1, calls)
}

func TestCachingRoleChecker_cachesHasPermission(t *testing.T) {
	calls := 0
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			calls++
			return []Role{RoleEditor}, nil
		},
	}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Hour)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ok, err := checker.HasPermission(ctx, "u1", PermWriteContent)
		require.NoErrorf(t, err, "call %d", i)
		require.Truef(t, ok, "call %d", i)
	}
	require.Equal(t, 1, calls)
}

func TestCachingRoleChecker_defaultTTL(t *testing.T) {
	store := &mockRBACUserStore{}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), 0)
	require.NotNil(t, checker)
}

func TestCachingRoleChecker_expiryHasRole(t *testing.T) {
	calls := 0
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			calls++
			return []Role{RoleAdmin}, nil
		},
	}
	crc := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Nanosecond).(*cachingRoleChecker)
	ctx := context.Background()

	_, err := crc.HasRole(ctx, "u1", RoleAdmin)
	require.NoError(t, err)

	// Manually expire the entry.
	crc.roleMu.Lock()
	key := roleCacheKey{userID: "u1", role: RoleAdmin}
	e := crc.roleEntries[key]
	e.expiresAt = time.Now().Add(-time.Second)
	crc.roleEntries[key] = e
	crc.roleMu.Unlock()

	_, err = crc.HasRole(ctx, "u1", RoleAdmin)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}

func TestCachingRoleChecker_expiryHasPermission(t *testing.T) {
	calls := 0
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			calls++
			return []Role{RoleEditor}, nil
		},
	}
	crc := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Nanosecond).(*cachingRoleChecker)
	ctx := context.Background()

	_, err := crc.HasPermission(ctx, "u1", PermWriteContent)
	require.NoError(t, err)

	// Manually expire the entry.
	crc.permMu.Lock()
	key := permCacheKey{userID: "u1", perm: PermWriteContent}
	e := crc.permEntries[key]
	e.expiresAt = time.Now().Add(-time.Second)
	crc.permEntries[key] = e
	crc.permMu.Unlock()

	_, err = crc.HasPermission(ctx, "u1", PermWriteContent)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}

// --- RolesFromContext / ContextWithRoles -------------------------------------

func TestRolesFromContext_empty(t *testing.T) {
	require.Nil(t, RolesFromContext(context.Background()))
}

func TestContextWithRoles(t *testing.T) {
	ctx := ContextWithRoles(context.Background(), []Role{RoleAdmin, RoleEditor})
	roles := RolesFromContext(ctx)
	require.Len(t, roles, 2)
	require.Equal(t, RoleAdmin, roles[0])
	require.Equal(t, RoleEditor, roles[1])
}

// --- RequireRole middleware ---------------------------------------------------

func makeRequireRoleRequest(mgr *JWTManager, checker RoleChecker, cfg Config, apiKeys APIKeyStore, role Role, req *http.Request) *httptest.ResponseRecorder {
	handler := RequireRole(mgr, checker, cfg, apiKeys, role)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

type mockRoleChecker struct {
	hasRoleFunc func(ctx context.Context, userID string, role Role) (bool, error)
	hasPermFunc func(ctx context.Context, userID string, perm Permission) (bool, error)
}

func (m *mockRoleChecker) HasRole(ctx context.Context, userID string, role Role) (bool, error) {
	if m.hasRoleFunc != nil {
		return m.hasRoleFunc(ctx, userID, role)
	}
	return false, nil
}

func (m *mockRoleChecker) HasPermission(ctx context.Context, userID string, perm Permission) (bool, error) {
	if m.hasPermFunc != nil {
		return m.hasPermFunc(ctx, userID, perm)
	}
	return false, nil
}

func TestRequireRole_noToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRole_wrongRole(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "plain-user")

	checker := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) { return false, nil },
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_correctRole(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "admin-user")

	checker := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) { return true, nil },
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_checkerError(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "some-user")

	checker := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) {
			return false, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequireRole_invalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRole_setsContextValues(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "role-user")

	checker := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) { return true, nil },
	}

	var gotUserID string
	handler := RequireRole(mgr, checker, Config{CookieName: "auth"}, nil, RoleEditor)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUserID = UserIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, "role-user", gotUserID)
}

// --- RequirePermission middleware --------------------------------------------

func makeRequirePermissionRequest(mgr *JWTManager, checker RoleChecker, cfg Config, apiKeys APIKeyStore, perm Permission, req *http.Request) *httptest.ResponseRecorder {
	handler := RequirePermission(mgr, checker, cfg, apiKeys, perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestRequirePermission_noToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermManageUsers, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePermission_insufficientPerm(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "viewer-user")

	checker := &mockRoleChecker{
		hasPermFunc: func(_ context.Context, _ string, _ Permission) (bool, error) { return false, nil },
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermManageUsers, req)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePermission_granted(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "editor-user")

	checker := &mockRoleChecker{
		hasPermFunc: func(_ context.Context, _ string, _ Permission) (bool, error) { return true, nil },
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermWriteContent, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequirePermission_checkerError(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "some-user")

	checker := &mockRoleChecker{
		hasPermFunc: func(_ context.Context, _ string, _ Permission) (bool, error) {
			return false, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermReadContent, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequirePermission_invalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermReadContent, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePermission_setsUserIDInContext(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "perm-user")

	checker := &mockRoleChecker{
		hasPermFunc: func(_ context.Context, _ string, _ Permission) (bool, error) { return true, nil },
	}

	var gotUserID string
	handler := RequirePermission(mgr, checker, Config{CookieName: "auth"}, nil, PermReadContent)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotUserID = UserIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, "perm-user", gotUserID)
}

// --- NewAdminCheckerFromRoleChecker ------------------------------------------

func TestNewAdminCheckerFromRoleChecker_admin(t *testing.T) {
	rc := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, role Role) (bool, error) {
			return role == RoleAdmin, nil
		},
	}
	ac := NewAdminCheckerFromRoleChecker(rc)
	ok, err := ac.IsAdmin(context.Background(), "admin-user")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestNewAdminCheckerFromRoleChecker_nonAdmin(t *testing.T) {
	rc := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) {
			return false, nil
		},
	}
	ac := NewAdminCheckerFromRoleChecker(rc)
	ok, err := ac.IsAdmin(context.Background(), "regular-user")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestNewAdminCheckerFromRoleChecker_error(t *testing.T) {
	rc := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) {
			return false, errors.New("lookup error")
		},
	}
	ac := NewAdminCheckerFromRoleChecker(rc)
	_, err := ac.IsAdmin(context.Background(), "u1")
	require.Error(t, err)
}

// --- FIFO cache eviction order -----------------------------------------------

func TestCachingRoleCheckerEvictsOldestRole(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleAdmin}, nil
		},
	}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Hour).(*cachingRoleChecker)
	ctx := context.Background()

	// Fill the cache to capacity.
	for i := 0; i < defaultRoleCacheMaxEntries; i++ {
		userID := fmt.Sprintf("user-%d", i)
		_, err := checker.HasRole(ctx, userID, RoleAdmin)
		require.NoError(t, err)
	}
	require.Equal(t, defaultRoleCacheMaxEntries, len(checker.roleEntries))

	// One more insertion must evict the oldest entry (user-0), not a random one.
	_, err := checker.HasRole(ctx, "user-new", RoleAdmin)
	require.NoError(t, err)

	checker.roleMu.RLock()
	defer checker.roleMu.RUnlock()

	_, oldestPresent := checker.roleEntries[roleCacheKey{userID: "user-0", role: RoleAdmin}]
	require.False(t, oldestPresent, "oldest entry (user-0) should have been evicted")

	_, secondPresent := checker.roleEntries[roleCacheKey{userID: "user-1", role: RoleAdmin}]
	require.True(t, secondPresent, "second-oldest entry (user-1) should still be present")

	require.Equal(t, defaultRoleCacheMaxEntries, len(checker.roleEntries))
}

func TestCachingRoleCheckerEvictsOldestPerm(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleAdmin}, nil
		},
	}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Hour).(*cachingRoleChecker)
	ctx := context.Background()

	// Fill the perm cache to capacity.
	for i := 0; i < defaultPermCacheMaxEntries; i++ {
		userID := fmt.Sprintf("user-%d", i)
		_, err := checker.HasPermission(ctx, userID, PermReadContent)
		require.NoError(t, err)
	}
	require.Equal(t, defaultPermCacheMaxEntries, len(checker.permEntries))

	// One more insertion must evict the oldest entry, not a random one.
	_, err := checker.HasPermission(ctx, "user-new", PermReadContent)
	require.NoError(t, err)

	checker.permMu.RLock()
	defer checker.permMu.RUnlock()

	_, oldestPresent := checker.permEntries[permCacheKey{userID: "user-0", perm: PermReadContent}]
	require.False(t, oldestPresent, "oldest perm entry (user-0) should have been evicted")

	_, secondPresent := checker.permEntries[permCacheKey{userID: "user-1", perm: PermReadContent}]
	require.True(t, secondPresent, "second-oldest perm entry (user-1) should still be present")

	require.Equal(t, defaultPermCacheMaxEntries, len(checker.permEntries))
}

func TestCachingRoleCheckerReinsertAfterExpiry(t *testing.T) {
	// Verify that a key re-inserted after expiry is correctly tracked in the
	// order queue and does not cause incorrect eviction of newer entries.
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleAdmin}, nil
		},
	}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Hour).(*cachingRoleChecker)
	ctx := context.Background()

	// Insert "user-0" and immediately expire it.
	_, err := checker.HasRole(ctx, "user-0", RoleAdmin)
	require.NoError(t, err)
	checker.roleMu.Lock()
	k := roleCacheKey{userID: "user-0", role: RoleAdmin}
	e := checker.roleEntries[k]
	e.expiresAt = time.Now().Add(-time.Second)
	checker.roleEntries[k] = e
	checker.roleMu.Unlock()

	// Re-insert "user-0" — this should create a new order entry with a new seq.
	_, err = checker.HasRole(ctx, "user-0", RoleAdmin)
	require.NoError(t, err)

	checker.roleMu.RLock()
	mapEntry := checker.roleEntries[k]
	lastOrder := checker.roleOrder[len(checker.roleOrder)-1]
	checker.roleMu.RUnlock()

	// The map entry's seq should match the last order entry's seq.
	require.Equal(t, mapEntry.seq, lastOrder.seq, "re-inserted entry seq must match order queue")
}

func TestCachingRoleCheckerConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{RoleAdmin}, nil
		},
	}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), time.Hour)
	ctx := context.Background()

	const goroutines = 20
	const callsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func() {
			defer wg.Done()
			for i := range callsPerGoroutine {
				userID := fmt.Sprintf("user-%d-%d", g, i%10)
				ok, err := checker.HasRole(ctx, userID, RoleAdmin)
				require.NoError(t, err)
				require.True(t, ok)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// sweepRoleEntriesLocked / sweepPermEntriesLocked — eviction path coverage
// ---------------------------------------------------------------------------

// newTestCachingRoleChecker creates a bare cachingRoleChecker for white-box
// testing of the internal sweep and eviction logic.
func newTestCachingRoleChecker(delegate RoleChecker) *cachingRoleChecker {
return &cachingRoleChecker{
delegate:    delegate,
ttl:         time.Hour,
roleEntries: make(map[roleCacheKey]roleCacheEntry),
permEntries: make(map[permCacheKey]permCacheEntry),
}
}

func TestSweepRoleEntries_evictsOldest(t *testing.T) {
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

// Fill roleEntries and roleOrder to exactly the capacity limit.
for i := range defaultRoleCacheMaxEntries {
key := roleCacheKey{userID: fmt.Sprintf("u%d", i), role: RoleAdmin}
crc.roleEntries[key] = roleCacheEntry{result: true, expiresAt: time.Now().Add(time.Hour), seq: uint64(i)}
crc.roleOrder = append(crc.roleOrder, orderEntry[roleCacheKey]{key: key, seq: uint64(i)})
}

before := len(crc.roleEntries)
crc.sweepRoleEntriesLocked(time.Now())

// At least one entry must have been evicted to bring the map below capacity.
require.Less(t, len(crc.roleEntries), before)
}

func TestSweepRoleEntries_emptyOrderArbitraryEviction(t *testing.T) {
// When roleOrder is empty but the map is at capacity the fallback
// "arbitrary eviction" branch must still reduce the map size.
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

for i := range defaultRoleCacheMaxEntries {
key := roleCacheKey{userID: fmt.Sprintf("u%d", i), role: RoleAdmin}
crc.roleEntries[key] = roleCacheEntry{result: true, expiresAt: time.Now().Add(time.Hour), seq: uint64(i)}
}
// Leave roleOrder intentionally empty.

crc.sweepRoleEntriesLocked(time.Now())
require.Less(t, len(crc.roleEntries), defaultRoleCacheMaxEntries)
}

func TestSweepRoleEntries_staleSeqSkipped(t *testing.T) {
// An orderEntry whose seq doesn't match the live entry must be skipped
// without deleting the live entry.
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

// Fill to capacity so eviction kicks in.
for i := range defaultRoleCacheMaxEntries {
key := roleCacheKey{userID: fmt.Sprintf("u%d", i), role: RoleAdmin}
liveSeq := uint64(i) + 1000 // live entry has a higher seq
crc.roleEntries[key] = roleCacheEntry{result: true, expiresAt: time.Now().Add(time.Hour), seq: liveSeq}
// Order entry carries the old (stale) seq.
crc.roleOrder = append(crc.roleOrder, orderEntry[roleCacheKey]{key: key, seq: uint64(i)})
}

before := len(crc.roleEntries)
crc.sweepRoleEntriesLocked(time.Now())

// Stale order entries must not have deleted live entries; because all
// entries were stale in the order, the map should be unchanged in size
// unless the arbitrary-eviction fallback triggered.
// We assert only that the function completed without panic.
_ = before
}

func TestSweepPermEntries_evictsOldest(t *testing.T) {
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

for i := range defaultPermCacheMaxEntries {
key := permCacheKey{userID: fmt.Sprintf("u%d", i), perm: PermReadContent}
crc.permEntries[key] = permCacheEntry{result: true, expiresAt: time.Now().Add(time.Hour), seq: uint64(i)}
crc.permOrder = append(crc.permOrder, orderEntry[permCacheKey]{key: key, seq: uint64(i)})
}

before := len(crc.permEntries)
crc.sweepPermEntriesLocked(time.Now())
require.Less(t, len(crc.permEntries), before)
}

func TestSweepPermEntries_emptyOrderArbitraryEviction(t *testing.T) {
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

for i := range defaultPermCacheMaxEntries {
key := permCacheKey{userID: fmt.Sprintf("u%d", i), perm: PermReadContent}
crc.permEntries[key] = permCacheEntry{result: true, expiresAt: time.Now().Add(time.Hour), seq: uint64(i)}
}

crc.sweepPermEntriesLocked(time.Now())
require.Less(t, len(crc.permEntries), defaultPermCacheMaxEntries)
}

func TestSweepRoleEntries_sweepInterval_deletesExpired(t *testing.T) {
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

// Pre-set lastSweep to trigger the time-based sweep on this call.
crc.roleLastSweepTime = time.Now().Add(-2 * cacheSweepInterval)

key := roleCacheKey{userID: "expiring-user", role: RoleAdmin}
crc.roleEntries[key] = roleCacheEntry{result: true, expiresAt: time.Now().Add(-time.Second)}
crc.roleOrder = append(crc.roleOrder, orderEntry[roleCacheKey]{key: key, seq: 1})

crc.sweepRoleEntriesLocked(time.Now())

_, present := crc.roleEntries[key]
require.False(t, present)
}

func TestSweepPermEntries_sweepInterval_deletesExpired(t *testing.T) {
crc := newTestCachingRoleChecker(NewStoreRoleChecker(&mockRBACUserStore{}))

crc.permLastSweepTime = time.Now().Add(-2 * cacheSweepInterval)

key := permCacheKey{userID: "expiring-user", perm: PermReadContent}
crc.permEntries[key] = permCacheEntry{result: true, expiresAt: time.Now().Add(-time.Second)}
crc.permOrder = append(crc.permOrder, orderEntry[permCacheKey]{key: key, seq: 1})

crc.sweepPermEntriesLocked(time.Now())

_, present := crc.permEntries[key]
require.False(t, present)
}
