package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	return "", "", ErrNotFound
}
func (m *mockAPIKeyStore) TouchAPIKeyLastUsed(ctx context.Context, id string) error {
	if m.touchFunc != nil {
		return m.touchFunc(ctx, id)
	}
	return nil
}
func (m *mockAPIKeyStore) DeleteAPIKey(ctx context.Context, id, userID string) error { return nil }

// --- mockSessionStore ----------------------------------------------------------

type mockSessionStore struct {
	findByIDFunc           func(ctx context.Context, id string) (*Session, error)
	findByRefreshTokenFunc func(ctx context.Context, hash string) (*Session, error)
	createFunc             func(ctx context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*Session, error)
	listFunc               func(ctx context.Context, userID string) ([]Session, error)
	deleteFunc             func(ctx context.Context, id, userID string) error
	deleteAllFunc          func(ctx context.Context, userID string) error
	deleteExpiredFunc      func(ctx context.Context) error
}

func (m *mockSessionStore) FindSessionByID(ctx context.Context, id string) (*Session, error) {
	if m.findByIDFunc != nil {
		return m.findByIDFunc(ctx, id)
	}
	return nil, ErrNotFound
}
func (m *mockSessionStore) FindSessionByRefreshTokenHash(ctx context.Context, hash string) (*Session, error) {
	if m.findByRefreshTokenFunc != nil {
		return m.findByRefreshTokenFunc(ctx, hash)
	}
	return nil, ErrNotFound
}
func (m *mockSessionStore) CreateSession(ctx context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*Session, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, refreshTokenHash, userAgent, ipAddress, expiresAt)
	}
	return &Session{ID: "sess-id", UserID: userID, ExpiresAt: expiresAt}, nil
}
func (m *mockSessionStore) ListSessionsByUser(ctx context.Context, userID string) ([]Session, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockSessionStore) DeleteSession(ctx context.Context, id, userID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id, userID)
	}
	return nil
}
func (m *mockSessionStore) DeleteAllSessionsByUser(ctx context.Context, userID string) error {
	if m.deleteAllFunc != nil {
		return m.deleteAllFunc(ctx, userID)
	}
	return nil
}
func (m *mockSessionStore) DeleteExpiredSessions(ctx context.Context) error {
	if m.deleteExpiredFunc != nil {
		return m.deleteExpiredFunc(ctx)
	}
	return nil
}

// --- context helpers -----------------------------------------------------------

func TestUserIDFromContextEmpty(t *testing.T) {
	ctx := context.Background()
	if got := UserIDFromContext(ctx); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestContextWithUserID(t *testing.T) {
	ctx := ContextWithUserID(context.Background(), "user-42")
	if got := UserIDFromContext(ctx); got != "user-42" {
		t.Errorf("expected %q, got %q", "user-42", got)
	}
}

// --- extractToken --------------------------------------------------------------

func TestExtractTokenFromHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")

	tok, src, _ := extractToken(req, "auth")
	if tok != "mytoken123" {
		t.Errorf("expected %q, got %q", "mytoken123", tok)
	}
	if src != tokenSourceHeader {
		t.Errorf("expected tokenSourceHeader, got %v", src)
	}
}

func TestExtractTokenFromCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "cookietoken"})

	tok, src, _ := extractToken(req, "auth")
	if tok != "cookietoken" {
		t.Errorf("expected %q, got %q", "cookietoken", tok)
	}
	if src != tokenSourceCookie {
		t.Errorf("expected tokenSourceCookie, got %v", src)
	}
}

func TestExtractTokenMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	tok, src, reason := extractToken(req, "auth")
	if tok != "" {
		t.Errorf("expected empty token, got %q", tok)
	}
	if src != tokenSourceNone {
		t.Errorf("expected tokenSourceNone, got %v", src)
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestExtractTokenHeaderTakesPrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer headertoken")
	req.AddCookie(&http.Cookie{Name: "auth", Value: "cookietoken"})

	tok, src, _ := extractToken(req, "auth")
	if tok != "headertoken" {
		t.Errorf("expected header token, got %q", tok)
	}
	if src != tokenSourceHeader {
		t.Errorf("expected tokenSourceHeader, got %v", src)
	}
}

func TestExtractTokenEmptyBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer   ")

	tok, src, _ := extractToken(req, "auth")
	if tok != "" {
		t.Errorf("expected empty token for whitespace bearer, got %q", tok)
	}
	if src != tokenSourceNone {
		t.Errorf("expected tokenSourceNone, got %v", src)
	}
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
	if !shouldTouchAPIKeyLastUsed(id, time.Now()) {
		t.Error("first call should return true")
	}
}

func TestShouldTouchAPIKeyLastUsedWithinInterval(t *testing.T) {
	id := "apikey-interval-" + t.Name()
	now := time.Now()
	shouldTouchAPIKeyLastUsed(id, now) // record first touch

	// Call again within the interval – should be suppressed.
	if shouldTouchAPIKeyLastUsed(id, now.Add(time.Minute)) {
		t.Error("second call within interval should return false")
	}
}

func TestShouldTouchAPIKeyLastUsedAfterInterval(t *testing.T) {
	id := "apikey-after-interval-" + t.Name()
	now := time.Now()
	shouldTouchAPIKeyLastUsed(id, now) // record first touch

	// Call again after the full interval has passed.
	if !shouldTouchAPIKeyLastUsed(id, now.Add(apiKeyTouchInterval+time.Second)) {
		t.Error("call after full interval should return true")
	}
}

// --- resolveUser --------------------------------------------------------------

func TestResolveUserValidJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	token, _ := mgr.CreateToken(ctx, "user-jwt")
	uid, _, err := resolveUser(ctx, token, tokenSourceHeader, mgr, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-jwt" {
		t.Errorf("expected %q, got %q", "user-jwt", uid)
	}
}

func TestResolveUserInvalidJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	_, _, err := resolveUser(ctx, "bad.token", tokenSourceHeader, mgr, nil, "")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestResolveUserAPIKeyFromHeader(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "user-from-key", "key-id-1", nil
		},
	}

	uid, _, err := resolveUser(ctx, "app_somehexkey", tokenSourceHeader, mgr, store, "app_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-from-key" {
		t.Errorf("expected %q, got %q", "user-from-key", uid)
	}
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
	_, _, err := resolveUser(ctx, "app_somehexkey", tokenSourceCookie, mgr, store, "app_")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for API key from cookie, got %v", err)
	}
}

func TestResolveUserAPIKeyNotFound(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{} // returns ErrNotFound by default

	_, _, err := resolveUser(ctx, "app_unknownkey", tokenSourceHeader, mgr, store, "app_")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
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

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddlewareInvalidToken(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if !strings.Contains(body["error"], "invalid or expired") {
		t.Errorf("unexpected error message: %q", body["error"])
	}
}

func TestMiddlewareValidJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "user-mw")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-User-ID"); got != "user-mw" {
		t.Errorf("expected userID %q in context, got %q", "user-mw", got)
	}
}

func TestMiddlewareValidCookieJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "cookie-user")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: token})
	w := makeMiddlewareRequest(mgr, Config{CookieName: "auth"}, nil, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
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

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminMiddlewareNonAdmin(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "plain-user")

	checker := &mockAdminChecker{isAdminFunc: func(_ context.Context, _ string) (bool, error) { return false, nil }}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, Config{CookieName: "auth"}, nil, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestAdminMiddlewareAdmin(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateToken(ctx, "admin-user")

	checker := &mockAdminChecker{isAdminFunc: func(_ context.Context, _ string) (bool, error) { return true, nil }}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, Config{CookieName: "auth"}, nil, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
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

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
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
		if err != nil || !ok {
			t.Fatalf("call %d: unexpected result err=%v ok=%v", i, err, ok)
		}
	}
	if calls != 1 {
		t.Errorf("expected 1 delegate call, got %d", calls)
	}
}

func TestCachingAdminCheckerDefaultTTL(t *testing.T) {
	// TTL <= 0 should default to 5s without panicking.
	delegate := &mockAdminChecker{}
	cached := newCachingAdminChecker(delegate, 0)
	if cached == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestCachingAdminCheckerDelegateError(t *testing.T) {
	delegate := &mockAdminChecker{
		isAdminFunc: func(_ context.Context, _ string) (bool, error) {
			return false, errors.New("delegate error")
		},
	}
	cached := newCachingAdminChecker(delegate, time.Hour)
	_, err := cached.IsAdmin(context.Background(), "u")
	if err == nil {
		t.Error("expected error from delegate")
	}
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
	if _, err := cached.IsAdmin(ctx, "u"); err != nil {
		t.Fatal(err)
	}

	// Manually expire the entry.
	cached.mu.Lock()
	e := cached.entries["u"]
	e.expiresAt = time.Now().Add(-time.Second)
	cached.entries["u"] = e
	cached.mu.Unlock()

	if _, err := cached.IsAdmin(ctx, "u"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("expected 2 delegate calls after expiry, got %d", calls)
	}
}

func TestResolveUserAPIKeyStoreError(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "", "", errors.New("db connection error")
		},
	}

	_, _, err := resolveUser(ctx, "app_somekey", tokenSourceHeader, mgr, store, "app_")
	if err == nil {
		t.Error("expected error from store")
	}
	if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken) {
		t.Error("store error should not be wrapped as ErrInvalidToken/ErrExpiredToken")
	}
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

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
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

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
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

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- Session validation in Middleware -----------------------------------------

func TestMiddlewareValidSessionJWT(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateTokenWithSession(ctx, "user-sess", "sess-abc")

	store := &mockSessionStore{
		findByIDFunc: func(_ context.Context, id string) (*Session, error) {
			if id == "sess-abc" {
				return &Session{ID: id, UserID: "user-sess", ExpiresAt: time.Now().Add(time.Hour)}, nil
			}
			return nil, ErrNotFound
		},
	}

	cfg := Config{CookieName: "auth", Sessions: store}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeMiddlewareRequest(mgr, cfg, nil, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-User-ID"); got != "user-sess" {
		t.Errorf("expected userID %q, got %q", "user-sess", got)
	}
}

func TestMiddlewareRevokedSession(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateTokenWithSession(ctx, "user-revoked", "sess-revoked")

	store := &mockSessionStore{
		// Session not found → revoked.
		findByIDFunc: func(_ context.Context, _ string) (*Session, error) {
			return nil, ErrNotFound
		},
	}

	cfg := Config{CookieName: "auth", Sessions: store}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeMiddlewareRequest(mgr, cfg, nil, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked session, got %d", w.Code)
	}
}

func TestMiddlewareExpiredSession(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateTokenWithSession(ctx, "user-expired", "sess-expired")

	store := &mockSessionStore{
		findByIDFunc: func(_ context.Context, id string) (*Session, error) {
			return &Session{ID: id, UserID: "user-expired", ExpiresAt: time.Now().Add(-time.Second)}, nil
		},
	}

	cfg := Config{CookieName: "auth", Sessions: store}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeMiddlewareRequest(mgr, cfg, nil, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired session, got %d", w.Code)
	}
}

func TestMiddlewareNoSessionStoreSkipsCheck(t *testing.T) {
	// Without a session store, no session check is performed even if jti is present.
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateTokenWithSession(ctx, "user-noss", "sess-noss")

	cfg := Config{CookieName: "auth"} // Sessions is nil
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeMiddlewareRequest(mgr, cfg, nil, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 without session store, got %d", w.Code)
	}
}

func TestMiddlewareAPIKeyBypassesSessionCheck(t *testing.T) {
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	apiStore := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "user-api", "key-id", nil
		},
	}
	sessStore := &mockSessionStore{
		findByIDFunc: func(_ context.Context, _ string) (*Session, error) {
			// Should never be called for API key requests.
			return nil, ErrNotFound
		},
	}

	cfg := Config{CookieName: "auth", APIKeyPrefix: "app_", Sessions: sessStore}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer app_somehexkey")

	handler := Middleware(mgr, cfg, apiStore)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-User-ID", UserIDFromContext(r.Context()))
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for API key, got %d", w.Code)
	}
	if got := w.Header().Get("X-User-ID"); got != "user-api" {
		t.Errorf("expected userID %q, got %q", "user-api", got)
	}
}

func TestAdminMiddlewareValidSession(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateTokenWithSession(ctx, "admin-user", "sess-admin")

	sessStore := &mockSessionStore{
		findByIDFunc: func(_ context.Context, id string) (*Session, error) {
			return &Session{ID: id, UserID: "admin-user", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	checker := &mockAdminChecker{isAdminFunc: func(_ context.Context, _ string) (bool, error) { return true, nil }}

	cfg := Config{CookieName: "auth", Sessions: sessStore}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, cfg, nil, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAdminMiddlewareRevokedSession(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")
	token, _ := mgr.CreateTokenWithSession(ctx, "admin-user", "sess-revoked-admin")

	sessStore := &mockSessionStore{
		findByIDFunc: func(_ context.Context, _ string) (*Session, error) {
			return nil, ErrNotFound
		},
	}
	checker := &mockAdminChecker{isAdminFunc: func(_ context.Context, _ string) (bool, error) { return true, nil }}

	cfg := Config{CookieName: "auth", Sessions: sessStore}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := makeAdminRequest(mgr, checker, cfg, nil, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked admin session, got %d", w.Code)
	}
}

// TestResolveUserJWTWithSessionID verifies that resolveUser returns the session
// ID embedded in the jti claim.
func TestResolveUserJWTWithSessionID(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	token, _ := mgr.CreateTokenWithSession(ctx, "user-jti", "sess-jti")
	uid, sessID, err := resolveUser(ctx, token, tokenSourceHeader, mgr, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != "user-jti" {
		t.Errorf("expected userID %q, got %q", "user-jti", uid)
	}
	if sessID != "sess-jti" {
		t.Errorf("expected sessionID %q, got %q", "sess-jti", sessID)
	}
}

// TestResolveUserAPIKeyHasNoSessionID verifies that API key auth returns an
// empty session ID.
func TestResolveUserAPIKeyHasNoSessionID(t *testing.T) {
	ctx := context.Background()
	mgr, _ := NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "testapp")

	store := &mockAPIKeyStore{
		validateFunc: func(_ context.Context, _ string) (string, string, error) {
			return "user-api", "key-id", nil
		},
	}

	_, sessID, err := resolveUser(ctx, "app_somehexkey", tokenSourceHeader, mgr, store, "app_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessID != "" {
		t.Errorf("expected empty sessionID for API key, got %q", sessID)
	}
}
