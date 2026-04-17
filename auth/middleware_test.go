package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- mock stores ----------------------------------------------------------------

type mockAPIKeyStore struct {
	validateFunc func(ctx context.Context, keyHash string) (string, string, error)
	touchFunc    func(ctx context.Context, id string) error
}

func (m *mockAPIKeyStore) CreateAPIKey(ctx context.Context, userID, name, keyHash, keyPrefix string) (*APIKey, error) {
	return nil, nil
}
func (m *mockAPIKeyStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error) {
	return nil, nil
}
func (m *mockAPIKeyStore) FindAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*APIKey, error) {
	return nil, nil
}
func (m *mockAPIKeyStore) ValidateAPIKey(ctx context.Context, keyHash string) (string, string, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, keyHash)
	}
	return "", "", sql.ErrNoRows
}
func (m *mockAPIKeyStore) TouchAPIKeyLastUsed(ctx context.Context, id string) error {
	if m.touchFunc != nil {
		return m.touchFunc(ctx, id)
	}
	return nil
}
func (m *mockAPIKeyStore) DeleteAPIKey(ctx context.Context, id, userID string) error { return nil }

// --- context helpers -----------------------------------------------------------

func TestUserIDFromContextEmpty(t *testing.T) {
	ctx := context.Background()
	require.Empty(t, UserIDFromContext(ctx))
}

func TestContextWithUserID(t *testing.T) {
	ctx := ContextWithUserID(context.Background(), "user-42")
	require.Equal(t, "user-42", UserIDFromContext(ctx))
}

// --- extractToken --------------------------------------------------------------

func TestExtractTokenFromHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")

	tok, src, _ := extractToken(req, "auth")
	require.Equal(t, "mytoken123", tok)
	require.Equal(t, tokenSourceHeader, src)
}

func TestExtractTokenFromCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "cookietoken"})

	tok, src, _ := extractToken(req, "auth")
	require.Equal(t, "cookietoken", tok)
	require.Equal(t, tokenSourceCookie, src)
}

func TestExtractTokenMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	tok, src, reason := extractToken(req, "auth")
	require.Empty(t, tok)
	require.Equal(t, tokenSourceNone, src)
	require.NotEmpty(t, reason)
}

func TestExtractTokenHeaderTakesPrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer headertoken")
	req.AddCookie(&http.Cookie{Name: "auth", Value: "cookietoken"})

	tok, src, _ := extractToken(req, "auth")
	require.Equal(t, "headertoken", tok)
	require.Equal(t, tokenSourceHeader, src)
}

func TestExtractTokenEmptyBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer   ")

	tok, src, _ := extractToken(req, "auth")
	require.Empty(t, tok)
	require.Equal(t, tokenSourceNone, src)
}

// --- shouldTouchAPIKeyLastUsed ------------------------------------------------

func init() {
	// Reset the global map before tests in this package run.
	apiKeyTouchMu.Lock()
	apiKeyLastTouchedAt = make(map[string]time.Time)
	apiKeyTouchMu.Unlock()
}

func TestShouldTouchAPIKeyLastUsedFirstTime(t *testing.T) {
	id := "apikey-first-time-" + t.Name()
	require.True(t, shouldTouchAPIKeyLastUsed(id, time.Now()))
}

func TestShouldTouchAPIKeyLastUsedWithinInterval(t *testing.T) {
	id := "apikey-interval-" + t.Name()
	now := time.Now()
	shouldTouchAPIKeyLastUsed(id, now) // record first touch

	// Call again within the interval – should be suppressed.
	require.False(t, shouldTouchAPIKeyLastUsed(id, now.Add(time.Minute)))
}

func TestShouldTouchAPIKeyLastUsedAfterInterval(t *testing.T) {
	id := "apikey-after-interval-" + t.Name()
	now := time.Now()
	shouldTouchAPIKeyLastUsed(id, now) // record first touch

	// Call again after the full interval has passed.
	require.True(t, shouldTouchAPIKeyLastUsed(id, now.Add(apiKeyTouchInterval+time.Second)))
}

// --- resolveUser --------------------------------------------------------------

func TestResolveUserValidJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	token, _ := mgr.CreateToken(ctx, "user-jwt")
	uid, err := resolveUser(ctx, token, tokenSourceHeader, mgr, nil, "")
	require.NoError(t, err)
	require.Equal(t, "user-jwt", uid)
}

func TestResolveUserInvalidJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, err := resolveUser(ctx, "bad.token", tokenSourceHeader, mgr, nil, "")
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestResolveUserAPIKeyFromHeader(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "user-from-key", "key-id-1", nil
		},
	}

	uid, err := resolveUser(ctx, "app_somehexkey", tokenSourceHeader, mgr, store, "app_")
	require.NoError(t, err)
	require.Equal(t, "user-from-key", uid)
}

func TestResolveUserAPIKeyFromCookieRejected(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "user-from-key", "key-id", nil
		},
	}

	// API keys in cookies must be rejected.
	_, err := resolveUser(ctx, "app_somehexkey", tokenSourceCookie, mgr, store, "app_")
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestResolveUserAPIKeyNotFound(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{} // returns sql.ErrNoRows by default

	_, err := resolveUser(ctx, "app_unknownkey", tokenSourceHeader, mgr, store, "app_")
	require.ErrorIs(t, err, ErrInvalidToken)
}

// --- Middleware ---------------------------------------------------------------

func makeMiddlewareRequest(mgr *JWTManager, cfg Config, apiKeys APIKeyStore, req *http.Request) *httptest.ResponseRecorder {
	handler := Middleware(mgr, cfg, apiKeys)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := UserIDFromContext(r.Context())
		w.Header().Set("X-User-ID", uid)
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestMiddlewareNoToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddlewareInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	require.Contains(t, body["error"], "invalid or expired")
}

func TestMiddlewareValidJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "user-mw")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "user-mw", w.Header().Get("X-User-ID"))
}

func TestMiddlewareValidCookieJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "cookie-user")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: token})
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusOK, w.Code)
}

// --- AdminMiddleware ----------------------------------------------------------

type mockAdminChecker struct {
	isAdminFunc func(ctx context.Context, userID string) (bool, error)
}

func (m *mockAdminChecker) IsAdmin(ctx context.Context, userID string) (bool, error) {
	if m.isAdminFunc != nil {
		return m.isAdminFunc(ctx, userID)
	}
	return false, nil
}

func makeAdminRequest(mgr *JWTManager, checker AdminChecker, cfg Config, apiKeys APIKeyStore, req *http.Request) *httptest.ResponseRecorder {
	handler := AdminMiddleware(mgr, checker, cfg, apiKeys)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestAdminMiddlewareNoToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockAdminChecker{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := makeAdminRequest(mgr, checker, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminMiddlewareNonAdmin(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "plain-user")

	checker := &mockAdminChecker{isAdminFunc: func(_ context.Context, _ string) (bool, error) { return false, nil }}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdminMiddlewareAdmin(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "admin-user")

	checker := &mockAdminChecker{isAdminFunc: func(_ context.Context, _ string) (bool, error) { return true, nil }}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestAdminMiddlewareCheckerError(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "some-user")

	checker := &mockAdminChecker{
		isAdminFunc: func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, Config{CookieName: "auth"}, nil, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- cachingAdminChecker ------------------------------------------------------

func TestCachingAdminCheckerCachesResult(t *testing.T) {
	calls := 0
	delegate := &mockAdminChecker{
		isAdminFunc: func(_ context.Context, _ string) (bool, error) {
			calls++
			return true, nil
		},
	}
	cached := newCachingAdminChecker(delegate, time.Hour)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		ok, err := cached.IsAdmin(ctx, "user-1")
		require.NoErrorf(t, err, "call %d", i)
		require.Truef(t, ok, "call %d", i)
	}
	require.Equal(t, 1, calls)
}

func TestCachingAdminCheckerDefaultTTL(t *testing.T) {
	// TTL <= 0 should default to 5s without panicking.
	delegate := &mockAdminChecker{}
	cached := newCachingAdminChecker(delegate, 0)
	require.NotNil(t, cached)
}

func TestCachingAdminCheckerDelegateError(t *testing.T) {
	delegate := &mockAdminChecker{
		isAdminFunc: func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("delegate error")
		},
	}
	cached := newCachingAdminChecker(delegate, time.Hour)
	_, err := cached.IsAdmin(context.Background(), "u")
	require.Error(t, err)
}

func TestCachingAdminCheckerExpiry(t *testing.T) {
	calls := 0
	delegate := &mockAdminChecker{
		isAdminFunc: func(_ context.Context, _ string) (bool, error) {
			calls++
			return true, nil
		},
	}
	// Very short TTL so we can test expiry without sleeping.
	cached := newCachingAdminChecker(delegate, time.Nanosecond).(*cachingAdminChecker)

	ctx := context.Background()
	b, err := cached.IsAdmin(ctx, "u")
	require.NoError(t, err)
	require.True(t, b)

	// Manually expire the entry.
	cached.mu.Lock()
	e := cached.entries["u"]
	e.expiresAt = time.Now().Add(-time.Second)
	cached.entries["u"] = e
	cached.mu.Unlock()

	c, err := cached.IsAdmin(ctx, "u")
	require.NoError(t, err)
	require.True(t, c)
	require.Equal(t, 2, calls)
}

func TestResolveUserAPIKeyStoreError(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "", "", errors.New("db connection error")
		},
	}

	_, err := resolveUser(ctx, "app_somekey", tokenSourceHeader, mgr, store, "app_")
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken))
}

func TestMiddlewareInternalError(t *testing.T) {
	// A store error in resolveUser that is not ErrInvalidToken should return 500.
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "", "", errors.New("db error")
		},
	}

	handler := Middleware(mgr, Config{CookieName: "auth", APIKeyPrefix: "app_"}, store)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer app_somevalidhexkey")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAdminMiddlewareInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	checker := &mockAdminChecker{}

	handler := AdminMiddleware(mgr, checker, Config{CookieName: "auth"}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminMiddlewareInternalError(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "", "", errors.New("db error")
		},
	}
	checker := &mockAdminChecker{}

	handler := AdminMiddleware(mgr, checker, Config{CookieName: "auth", APIKeyPrefix: "app_"}, store)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer app_anykeyhere")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}
