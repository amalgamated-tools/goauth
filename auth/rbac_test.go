package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestStoreRoleCheckerHasRole(t *testing.T) {
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

func TestStoreRoleCheckerHasRoleError(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return nil, errors.New("db error")
		},
	}
	checker := NewStoreRoleChecker(store)
	_, err := checker.HasRole(context.Background(), "u1", RoleAdmin)
	require.Error(t, err)
}

func TestStoreRoleCheckerHasPermission(t *testing.T) {
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

func TestStoreRoleCheckerHasPermissionMultiRole(t *testing.T) {
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

func TestStoreRoleCheckerHasPermissionUnknownRole(t *testing.T) {
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

func TestStoreRoleCheckerHasPermissionError(t *testing.T) {
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

func TestCachingRoleCheckerCachesHasRole(t *testing.T) {
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

func TestCachingRoleCheckerCachesHasPermission(t *testing.T) {
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

func TestCachingRoleCheckerDefaultTTL(t *testing.T) {
	store := &mockRBACUserStore{}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), 0)
	require.NotNil(t, checker)
}

func TestCachingRoleCheckerExpiryHasRole(t *testing.T) {
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

func TestCachingRoleCheckerExpiryHasPermission(t *testing.T) {
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

func TestRolesFromContextEmpty(t *testing.T) {
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

func TestRequireRoleNoToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRoleWrongRole(t *testing.T) {
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

func TestRequireRoleCorrectRole(t *testing.T) {
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

func TestRequireRoleCheckerError(t *testing.T) {
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

func TestRequireRoleInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRoleSetsContextValues(t *testing.T) {
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

func TestRequirePermissionNoToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermManageUsers, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePermissionInsufficientPerm(t *testing.T) {
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

func TestRequirePermissionGranted(t *testing.T) {
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

func TestRequirePermissionCheckerError(t *testing.T) {
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

func TestRequirePermissionInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermReadContent, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePermissionSetsUserIDInContext(t *testing.T) {
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

func TestNewAdminCheckerFromRoleCheckerAdmin(t *testing.T) {
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

func TestNewAdminCheckerFromRoleCheckerNonAdmin(t *testing.T) {
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

func TestNewAdminCheckerFromRoleCheckerError(t *testing.T) {
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
