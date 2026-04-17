package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	if err != nil || !ok {
		t.Errorf("expected (true, nil), got (%v, %v)", ok, err)
	}

	ok, err = checker.HasRole(ctx, "u1", RoleAdmin)
	if err != nil || ok {
		t.Errorf("expected (false, nil), got (%v, %v)", ok, err)
	}
}

func TestStoreRoleCheckerHasRoleError(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return nil, errors.New("db error")
		},
	}
	checker := NewStoreRoleChecker(store)
	_, err := checker.HasRole(context.Background(), "u1", RoleAdmin)
	if err == nil {
		t.Error("expected error")
	}
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
	if err != nil || !ok {
		t.Errorf("expected (true, nil), got (%v, %v)", ok, err)
	}

	ok, err = checker.HasPermission(ctx, "u1", PermManageUsers)
	if err != nil || ok {
		t.Errorf("expected (false, nil), got (%v, %v)", ok, err)
	}
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
	if err != nil || !ok {
		t.Errorf("expected (true, nil), got (%v, %v)", ok, err)
	}
}

func TestStoreRoleCheckerHasPermissionUnknownRole(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return []Role{Role("nonexistent")}, nil
		},
	}
	checker := NewStoreRoleChecker(store)
	ok, err := checker.HasPermission(context.Background(), "u1", PermReadContent)
	if err != nil || ok {
		t.Errorf("expected (false, nil) for unknown role, got (%v, %v)", ok, err)
	}
}

func TestStoreRoleCheckerHasPermissionError(t *testing.T) {
	store := &mockRBACUserStore{
		getRolesFunc: func(_ context.Context, _ string) ([]Role, error) {
			return nil, errors.New("db error")
		},
	}
	checker := NewStoreRoleChecker(store)
	_, err := checker.HasPermission(context.Background(), "u1", PermReadContent)
	if err == nil {
		t.Error("expected error")
	}
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
	if err != nil || !ok {
		t.Errorf("expected (true, nil) for custom role/perm, got (%v, %v)", ok, err)
	}
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
		if err != nil || !ok {
			t.Fatalf("call %d: unexpected result err=%v ok=%v", i, err, ok)
		}
	}
	// StoreRoleChecker calls GetRoles once per HasRole, but caching wrapper
	// should only call through on the first request.
	if calls != 1 {
		t.Errorf("expected 1 delegate call, got %d", calls)
	}
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
		if err != nil || !ok {
			t.Fatalf("call %d: unexpected result err=%v ok=%v", i, err, ok)
		}
	}
	if calls != 1 {
		t.Errorf("expected 1 delegate call, got %d", calls)
	}
}

func TestCachingRoleCheckerDefaultTTL(t *testing.T) {
	store := &mockRBACUserStore{}
	checker := NewCachingRoleChecker(NewStoreRoleChecker(store), 0)
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
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

	crc.HasRole(ctx, "u1", RoleAdmin)

	// Manually expire the entry.
	crc.roleMu.Lock()
	key := roleCacheKey{userID: "u1", role: RoleAdmin}
	e := crc.roleEntries[key]
	e.expiresAt = time.Now().Add(-time.Second)
	crc.roleEntries[key] = e
	crc.roleMu.Unlock()

	crc.HasRole(ctx, "u1", RoleAdmin)
	if calls != 2 {
		t.Errorf("expected 2 delegate calls after expiry, got %d", calls)
	}
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

	crc.HasPermission(ctx, "u1", PermWriteContent)

	// Manually expire the entry.
	crc.permMu.Lock()
	key := permCacheKey{userID: "u1", perm: PermWriteContent}
	e := crc.permEntries[key]
	e.expiresAt = time.Now().Add(-time.Second)
	crc.permEntries[key] = e
	crc.permMu.Unlock()

	crc.HasPermission(ctx, "u1", PermWriteContent)
	if calls != 2 {
		t.Errorf("expected 2 delegate calls after expiry, got %d", calls)
	}
}

// --- RolesFromContext / ContextWithRoles -------------------------------------

func TestRolesFromContextEmpty(t *testing.T) {
	if roles := RolesFromContext(context.Background()); roles != nil {
		t.Errorf("expected nil, got %v", roles)
	}
}

func TestContextWithRoles(t *testing.T) {
	ctx := ContextWithRoles(context.Background(), []Role{RoleAdmin, RoleEditor})
	roles := RolesFromContext(ctx)
	if len(roles) != 2 || roles[0] != RoleAdmin || roles[1] != RoleEditor {
		t.Errorf("unexpected roles: %v", roles)
	}
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
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
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
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
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
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRequireRoleInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeRequireRoleRequest(mgr, checker, Config{CookieName: "auth"}, nil, RoleAdmin, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
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

	if gotUserID != "role-user" {
		t.Errorf("expected userID %q, got %q", "role-user", gotUserID)
	}
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
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
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
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
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
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
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
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRequirePermissionInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockRoleChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeRequirePermissionRequest(mgr, checker, Config{CookieName: "auth"}, nil, PermReadContent, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
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

	if gotUserID != "perm-user" {
		t.Errorf("expected userID %q, got %q", "perm-user", gotUserID)
	}
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
	if err != nil || !ok {
		t.Errorf("expected (true, nil), got (%v, %v)", ok, err)
	}
}

func TestNewAdminCheckerFromRoleCheckerNonAdmin(t *testing.T) {
	rc := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) {
			return false, nil
		},
	}
	ac := NewAdminCheckerFromRoleChecker(rc)
	ok, err := ac.IsAdmin(context.Background(), "regular-user")
	if err != nil || ok {
		t.Errorf("expected (false, nil), got (%v, %v)", ok, err)
	}
}

func TestNewAdminCheckerFromRoleCheckerError(t *testing.T) {
	rc := &mockRoleChecker{
		hasRoleFunc: func(_ context.Context, _ string, _ Role) (bool, error) {
			return false, errors.New("lookup error")
		},
	}
	ac := NewAdminCheckerFromRoleChecker(rc)
	_, err := ac.IsAdmin(context.Background(), "u1")
	if err == nil {
		t.Error("expected error from role checker")
	}
}
