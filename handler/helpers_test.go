package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// shared mock stores (used across auth_test.go, apikey_test.go, etc.)
// ---------------------------------------------------------------------------

type mockUserStore struct {
	createUserFunc        func(ctx context.Context, name, email, passwordHash string) (*auth.User, error)
	createOIDCUserFunc    func(ctx context.Context, name, email, oidcSubject string) (*auth.User, error)
	findByEmailFunc       func(ctx context.Context, email string) (*auth.User, error)
	findByIDFunc          func(ctx context.Context, id string) (*auth.User, error)
	findByOIDCSubjectFunc func(ctx context.Context, subject string) (*auth.User, error)
	linkOIDCSubjectFunc   func(ctx context.Context, userID, oidcSubject string) error
	updatePasswordFunc    func(ctx context.Context, userID, passwordHash string) error
	updateNameFunc        func(ctx context.Context, userID, name string) (*auth.User, error)
	isAdminFunc           func(ctx context.Context, userID string) (bool, error)
	countUsersFunc        func(ctx context.Context) (int, error)
}

func (m *mockUserStore) CreateUser(ctx context.Context, name, email, hash string) (*auth.User, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, name, email, hash)
	}
	return &auth.User{ID: "new-id", Name: name, Email: email, PasswordHash: hash}, nil
}
func (m *mockUserStore) CreateOIDCUser(ctx context.Context, name, email, sub string) (*auth.User, error) {
	if m.createOIDCUserFunc != nil {
		return m.createOIDCUserFunc(ctx, name, email, sub)
	}
	return &auth.User{ID: "oidc-id", Name: name, Email: email}, nil
}
func (m *mockUserStore) FindByEmail(ctx context.Context, email string) (*auth.User, error) {
	if m.findByEmailFunc != nil {
		return m.findByEmailFunc(ctx, email)
	}
	return nil, nil
}
func (m *mockUserStore) FindByID(ctx context.Context, id string) (*auth.User, error) {
	if m.findByIDFunc != nil {
		return m.findByIDFunc(ctx, id)
	}
	return &auth.User{ID: id}, nil
}
func (m *mockUserStore) FindByOIDCSubject(ctx context.Context, sub string) (*auth.User, error) {
	if m.findByOIDCSubjectFunc != nil {
		return m.findByOIDCSubjectFunc(ctx, sub)
	}
	return nil, nil
}
func (m *mockUserStore) LinkOIDCSubject(ctx context.Context, userID, sub string) error {
	if m.linkOIDCSubjectFunc != nil {
		return m.linkOIDCSubjectFunc(ctx, userID, sub)
	}
	return nil
}
func (m *mockUserStore) UpdatePassword(ctx context.Context, userID, hash string) error {
	if m.updatePasswordFunc != nil {
		return m.updatePasswordFunc(ctx, userID, hash)
	}
	return nil
}
func (m *mockUserStore) UpdateName(ctx context.Context, userID, name string) (*auth.User, error) {
	if m.updateNameFunc != nil {
		return m.updateNameFunc(ctx, userID, name)
	}
	return &auth.User{ID: userID, Name: name}, nil
}
func (m *mockUserStore) IsAdmin(ctx context.Context, userID string) (bool, error) {
	if m.isAdminFunc != nil {
		return m.isAdminFunc(ctx, userID)
	}
	return false, nil
}
func (m *mockUserStore) CountUsers(ctx context.Context) (int, error) {
	if m.countUsersFunc != nil {
		return m.countUsersFunc(ctx)
	}
	return 0, nil
}

type mockAPIKeyStore struct {
	createFunc   func(ctx context.Context, userID, name, keyHash, keyPrefix string) (*auth.APIKey, error)
	listFunc     func(ctx context.Context, userID string) ([]auth.APIKey, error)
	findFunc     func(ctx context.Context, id, userID string) (*auth.APIKey, error)
	validateFunc func(ctx context.Context, keyHash string) (string, string, error)
	touchFunc    func(ctx context.Context, id string) error
	deleteFunc   func(ctx context.Context, id, userID string) error
}

func (m *mockAPIKeyStore) CreateAPIKey(ctx context.Context, userID, name, keyHash, keyPrefix string) (*auth.APIKey, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, name, keyHash, keyPrefix)
	}
	return &auth.APIKey{ID: "key-id", UserID: userID, Name: name, KeyPrefix: keyPrefix, CreatedAt: time.Now()}, nil
}
func (m *mockAPIKeyStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]auth.APIKey, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockAPIKeyStore) FindAPIKeyByIDAndUser(ctx context.Context, id, userID string) (*auth.APIKey, error) {
	if m.findFunc != nil {
		return m.findFunc(ctx, id, userID)
	}
	return nil, nil
}
func (m *mockAPIKeyStore) ValidateAPIKey(ctx context.Context, keyHash string) (string, string, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, keyHash)
	}
	return "", "", nil
}
func (m *mockAPIKeyStore) TouchAPIKeyLastUsed(ctx context.Context, id string) error {
	if m.touchFunc != nil {
		return m.touchFunc(ctx, id)
	}
	return nil
}
func (m *mockAPIKeyStore) DeleteAPIKey(ctx context.Context, id, userID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id, userID)
	}
	return nil
}

type mockSessionStore struct {
	createFunc             func(ctx context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*auth.Session, error)
	findByIDFunc           func(ctx context.Context, id string) (*auth.Session, error)
	findByRefreshTokenFunc func(ctx context.Context, hash string) (*auth.Session, error)
	listFunc               func(ctx context.Context, userID string) ([]auth.Session, error)
	deleteFunc             func(ctx context.Context, id, userID string) error
	deleteAllFunc          func(ctx context.Context, userID string) error
	deleteExpiredFunc      func(ctx context.Context) error
}

func (m *mockSessionStore) CreateSession(ctx context.Context, userID, refreshTokenHash, userAgent, ipAddress string, expiresAt time.Time) (*auth.Session, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, refreshTokenHash, userAgent, ipAddress, expiresAt)
	}
	return &auth.Session{ID: "sess-id", UserID: userID, ExpiresAt: expiresAt}, nil
}
func (m *mockSessionStore) FindSessionByID(ctx context.Context, id string) (*auth.Session, error) {
	if m.findByIDFunc != nil {
		return m.findByIDFunc(ctx, id)
	}
	return nil, nil
}
func (m *mockSessionStore) FindSessionByRefreshTokenHash(ctx context.Context, hash string) (*auth.Session, error) {
	if m.findByRefreshTokenFunc != nil {
		return m.findByRefreshTokenFunc(ctx, hash)
	}
	return nil, nil
}
func (m *mockSessionStore) ListSessionsByUser(ctx context.Context, userID string) ([]auth.Session, error) {
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

type mockMagicLinkStore struct {
	createFunc        func(ctx context.Context, email, tokenHash string, expiresAt time.Time) (*auth.MagicLink, error)
	findAndDeleteFunc func(ctx context.Context, tokenHash string) (*auth.MagicLink, error)
	deleteExpiredFunc func(ctx context.Context) error
}

func (m *mockMagicLinkStore) CreateMagicLink(ctx context.Context, email, tokenHash string, expiresAt time.Time) (*auth.MagicLink, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, email, tokenHash, expiresAt)
	}
	return &auth.MagicLink{ID: "ml-id", Email: email, TokenHash: tokenHash, ExpiresAt: expiresAt}, nil
}
func (m *mockMagicLinkStore) FindAndDeleteMagicLink(ctx context.Context, tokenHash string) (*auth.MagicLink, error) {
	if m.findAndDeleteFunc != nil {
		return m.findAndDeleteFunc(ctx, tokenHash)
	}
	return nil, auth.ErrNotFound
}
func (m *mockMagicLinkStore) DeleteExpiredMagicLinks(ctx context.Context) error {
	if m.deleteExpiredFunc != nil {
		return m.deleteExpiredFunc(ctx)
	}
	return nil
}

type mockOIDCLinkNonceStore struct {
	nonces               map[string]*auth.OIDCLinkNonce
	createFunc           func(ctx context.Context, userID, nonceHash string, expiresAt time.Time) (*auth.OIDCLinkNonce, error)
	consumeAndDeleteFunc func(ctx context.Context, nonceHash string) (*auth.OIDCLinkNonce, error)
	deleteExpiredFunc    func(ctx context.Context) error
}

func (m *mockOIDCLinkNonceStore) CreateLinkNonce(ctx context.Context, userID, nonceHash string, expiresAt time.Time) (*auth.OIDCLinkNonce, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, nonceHash, expiresAt)
	}
	n := &auth.OIDCLinkNonce{ID: "nonce-id", UserID: userID, NonceHash: nonceHash, ExpiresAt: expiresAt}
	if m.nonces == nil {
		m.nonces = make(map[string]*auth.OIDCLinkNonce)
	}
	m.nonces[nonceHash] = n
	return n, nil
}

func (m *mockOIDCLinkNonceStore) ConsumeAndDeleteLinkNonce(ctx context.Context, nonceHash string) (*auth.OIDCLinkNonce, error) {
	if m.consumeAndDeleteFunc != nil {
		return m.consumeAndDeleteFunc(ctx, nonceHash)
	}
	if m.nonces == nil {
		return nil, auth.ErrNotFound
	}
	n, ok := m.nonces[nonceHash]
	if !ok {
		return nil, auth.ErrNotFound
	}
	delete(m.nonces, nonceHash)
	return n, nil
}

func (m *mockOIDCLinkNonceStore) DeleteExpiredLinkNonces(ctx context.Context) error {
	if m.deleteExpiredFunc != nil {
		return m.deleteExpiredFunc(ctx)
	}
	return nil
}

type mockPasswordResetStore struct {
	createFunc        func(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.PasswordResetToken, error)
	findFunc          func(ctx context.Context, tokenHash string) (*auth.PasswordResetToken, error)
	deleteFunc        func(ctx context.Context, id string) error
	deleteExpiredFunc func(ctx context.Context) error
}

func (m *mockPasswordResetStore) CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.PasswordResetToken, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, userID, tokenHash, expiresAt)
	}
	return &auth.PasswordResetToken{ID: "reset-id", UserID: userID, TokenHash: tokenHash, ExpiresAt: expiresAt}, nil
}
func (m *mockPasswordResetStore) FindPasswordResetToken(ctx context.Context, tokenHash string) (*auth.PasswordResetToken, error) {
	if m.findFunc != nil {
		return m.findFunc(ctx, tokenHash)
	}
	return nil, auth.ErrInvalidToken
}
func (m *mockPasswordResetStore) DeletePasswordResetToken(ctx context.Context, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	return nil
}
func (m *mockPasswordResetStore) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	if m.deleteExpiredFunc != nil {
		return m.deleteExpiredFunc(ctx)
	}
	return nil
}

// mockTokenCreator is a test double for tokenCreator.
type mockTokenCreator struct {
	createTokenFunc            func(ctx context.Context, userID string) (string, error)
	createTokenWithSessionFunc func(ctx context.Context, userID, sessionID string) (string, error)
}

func (m *mockTokenCreator) CreateToken(ctx context.Context, userID string) (string, error) {
	if m.createTokenFunc != nil {
		return m.createTokenFunc(ctx, userID)
	}
	return newTestJWT().CreateToken(ctx, userID)
}

func (m *mockTokenCreator) CreateTokenWithSession(ctx context.Context, userID, sessionID string) (string, error) {
	if m.createTokenWithSessionFunc != nil {
		return m.createTokenWithSessionFunc(ctx, userID, sessionID)
	}
	return newTestJWT().CreateTokenWithSession(ctx, userID, sessionID)
}

func newAuthHandlerWithSessions(store auth.UserStore, sessions auth.SessionStore) *AuthHandler {
	return &AuthHandler{
		Users:             store,
		JWT:               newTestJWT(),
		Sessions:          sessions,
		CookieName:        "auth",
		RefreshCookieName: "refresh",
		SecureCookies:     false,
	}
}

// newTestJWT creates a JWTManager for handler tests.
func newTestJWT() *auth.JWTManager {
	mgr, _ := auth.NewJWTManager("test-secret-32-bytes-long-here!!", time.Hour, "test")
	return mgr
}

// postJSON performs a POST with a JSON body through the given handler.
func postJSON(t *testing.T, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// withUserID attaches a user ID to the request context.
func withUserID(req *http.Request, userID string) *http.Request {
	return req.WithContext(auth.ContextWithUserID(req.Context(), userID))
}

// ---------------------------------------------------------------------------
// writeJSON / writeError
// ---------------------------------------------------------------------------

func TestWriteJSON_setsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(context.Background(), w, http.StatusCreated, map[string]string{"key": "val"})

	require.Equal(t, http.StatusCreated, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Equal(t, "val", body["key"])
}

func TestWriteError_writesErrorField(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(context.Background(), w, http.StatusBadRequest, "bad input")

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Equal(t, "bad input", body["error"])
}

// ---------------------------------------------------------------------------
// decodeJSON
// ---------------------------------------------------------------------------

func TestDecodeJSON_valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Alice"}`))
	w := httptest.NewRecorder()
	var v struct{ Name string }
	require.True(t, decodeJSON(req, w, &v))
	require.Equal(t, "Alice", v.Name)
}

func TestDecodeJSON_invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	require.False(t, decodeJSON(req, w, &struct{}{}))
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// validatePassword
// ---------------------------------------------------------------------------

func TestValidatePassword_tooShort(t *testing.T) {
	w := httptest.NewRecorder()
	require.False(t, validatePassword(context.Background(), w, "short"))
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidatePassword_tooLong(t *testing.T) {
	w := httptest.NewRecorder()
	require.False(t, validatePassword(context.Background(), w, strings.Repeat("a", 73)))
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidatePassword_boundaries(t *testing.T) {
	for _, tc := range []struct {
		pw   string
		want bool
	}{
		{strings.Repeat("a", 7), false},  // one below min
		{strings.Repeat("a", 8), true},   // min
		{strings.Repeat("a", 72), true},  // max
		{strings.Repeat("a", 73), false}, // one above max
	} {
		w := httptest.NewRecorder()
		got := validatePassword(context.Background(), w, tc.pw)
		require.Equalf(t, tc.want, got, "len=%d", len(tc.pw))
	}
}

// ---------------------------------------------------------------------------
// SetAuthCookie / ClearAuthCookie
// ---------------------------------------------------------------------------

func TestSetAuthCookie_setsHttpOnly(t *testing.T) {
	w := httptest.NewRecorder()
	SetAuthCookie(w, "mytoken", "auth", false)

	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	require.NotNil(t, found)
	require.Equal(t, "mytoken", found.Value)
	require.True(t, found.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, found.SameSite)
}

func TestClearAuthCookie_setsNegativeMaxAge(t *testing.T) {
	w := httptest.NewRecorder()
	ClearAuthCookie(w, "auth", false)

	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	require.NotNil(t, found)
	require.Equal(t, -1, found.MaxAge)
	require.Empty(t, found.Value)
}

// ---------------------------------------------------------------------------
// ToUserDTO
// ---------------------------------------------------------------------------

func TestToUserDTO_withOidc(t *testing.T) {
	sub := "oidc-sub"
	u := &auth.User{ID: "u1", Name: "Alice", Email: "alice@example.com", OIDCSubject: &sub, IsAdmin: true}
	dto := ToUserDTO(u)
	require.Equal(t, "u1", dto.ID)
	require.Equal(t, "Alice", dto.Name)
	require.Equal(t, "alice@example.com", dto.Email)
	require.True(t, dto.OIDCLinked)
	require.True(t, dto.IsAdmin)
}

func TestToUserDTO_withoutOidc(t *testing.T) {
	u := &auth.User{ID: "u2", Name: "Bob", Email: "bob@example.com"}
	dto := ToUserDTO(u)
	require.False(t, dto.OIDCLinked)
	require.False(t, dto.IsAdmin)
}

// ---------------------------------------------------------------------------
// issueTokens
// ---------------------------------------------------------------------------

func TestIssueTokens_noSessions(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	access, refresh, ok := issueTokens(w, req, "user-1", nil, newTestJWT(), "auth", false, "", 0)

	require.True(t, ok)
	require.NotEmpty(t, access)
	require.Empty(t, refresh)

	var authCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			authCookie = c
		}
	}
	require.NotNil(t, authCookie)
	require.NotEmpty(t, authCookie.Value)

	// No refresh cookie.
	for _, c := range w.Result().Cookies() {
		require.NotEqual(t, "refresh", c.Name)
	}
}

func TestIssueTokens_withSessions_refreshCookie(t *testing.T) {
	sessions := &mockSessionStore{}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	access, refresh, ok := issueTokens(w, req, "user-1", sessions, newTestJWT(), "auth", false, "refresh", time.Hour)

	require.True(t, ok)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	var authCookie, refreshCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "auth":
			authCookie = c
		case "refresh":
			refreshCookie = c
		}
	}
	require.NotNil(t, authCookie)
	require.NotNil(t, refreshCookie)
	require.NotEmpty(t, refreshCookie.Value)
}

func TestIssueTokens_withSessions_noRefreshCookieName(t *testing.T) {
	// When Sessions is set but RefreshCookieName is empty, issueTokens fails
	// fast to prevent silent session leaks. Callers must set RefreshCookieName
	// when using session tracking.
	sessions := &mockSessionStore{}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	access, refresh, ok := issueTokens(w, req, "user-1", sessions, newTestJWT(), "auth", false, "", time.Hour)

	require.False(t, ok)
	require.Empty(t, access)
	require.Empty(t, refresh)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
