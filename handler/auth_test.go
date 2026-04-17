package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"golang.org/x/crypto/bcrypt"
)

func newAuthHandler(store auth.UserStore) *AuthHandler {
	return &AuthHandler{
		Users:         store,
		JWT:           newTestJWT(),
		CookieName:    "auth",
		SecureCookies: false,
	}
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

func TestSignupSuccess(t *testing.T) {
	store := &mockUserStore{}
	h := newAuthHandler(store)

	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty token in response")
	}
	if resp.User.Email != "alice@test.com" {
		t.Errorf("expected email alice@test.com, got %q", resp.User.Email)
	}
}

func TestSignupSetsAuthCookie(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	if found == nil || found.Value == "" {
		t.Error("expected auth cookie to be set on signup")
	}
}

func TestSignupDisabled(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	h.DisableSignup = true
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestSignupMissingName(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"","email":"a@b.com","password":"password123"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSignupMissingEmail(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"","password":"password123"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSignupMissingPassword(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"a@b.com","password":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSignupWeakPassword(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"a@b.com","password":"short"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSignupEmailConflict(t *testing.T) {
	store := &mockUserStore{
		createUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, auth.ErrEmailExists
		},
	}
	w := postJSON(t, newAuthHandler(store).Signup,
		`{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestSignupStoreError(t *testing.T) {
	store := &mockUserStore{
		createUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newAuthHandler(store).Signup,
		`{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestSignupInvalidJSON(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func hashPassword(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func TestLoginSuccess(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"alice@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestLoginSetsAuthCookie(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"alice@test.com","password":"goodpassword123"}`)
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	if found == nil || found.Value == "" {
		t.Error("expected auth cookie on login")
	}
}

func TestLoginMissingFields(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	for _, body := range []string{
		`{"email":"","password":"goodpassword123"}`,
		`{"email":"a@b.com","password":""}`,
	} {
		w := postJSON(t, h.Login, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: expected 400, got %d", body, w.Code)
		}
	}
}

func TestLoginUserNotFound(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"nope@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	hash := hashPassword(t, "correctpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "a@b.com", PasswordHash: hash}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"wrongpassword123"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLoginOIDCOnlyAccount(t *testing.T) {
	// User with no password hash (OIDC-only).
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "a@b.com", PasswordHash: ""}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"goodpassword123"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for OIDC-only account, got %d", w.Code)
	}
}

func TestLoginStoreError(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"goodpassword123"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Login, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

func TestLogout(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	if found == nil {
		t.Fatal("expected auth cookie to be cleared")
	}
	if found.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", found.MaxAge)
	}
}

// ---------------------------------------------------------------------------
// Me
// ---------------------------------------------------------------------------

func TestMeSuccess(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, Name: "Alice", Email: "alice@test.com"}, nil
		},
	}
	h := newAuthHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.Me(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var dto UserDTO
	_ = json.NewDecoder(w.Body).Decode(&dto)
	if dto.Email != "alice@test.com" {
		t.Errorf("expected email, got %q", dto.Email)
	}
}

func TestMeNotFound(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = withUserID(req, "unknown")
	w := httptest.NewRecorder()
	newAuthHandler(store).Me(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestMeStoreError(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).Me(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UpdateProfile
// ---------------------------------------------------------------------------

func TestUpdateProfileSuccess(t *testing.T) {
	store := &mockUserStore{}
	h := newAuthHandler(store)

	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"name":"Bob"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var dto UserDTO
	_ = json.NewDecoder(w.Body).Decode(&dto)
	if dto.Name != "Bob" {
		t.Errorf("expected name Bob, got %q", dto.Name)
	}
}

func TestUpdateProfileEmptyName(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"name":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).UpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateProfileInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader("bad"))
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).UpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ChangePassword
// ---------------------------------------------------------------------------

func TestChangePasswordSuccess(t *testing.T) {
	oldHash := hashPassword(t, "oldpassword123")
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: oldHash}, nil
		},
	}
	h := newAuthHandler(store)

	body := `{"currentPassword":"oldpassword123","newPassword":"newpassword456"}`
	req := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestChangePasswordMissingFields(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	for _, body := range []string{
		`{"currentPassword":"","newPassword":"newpassword456"}`,
		`{"currentPassword":"oldpassword123","newPassword":""}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withUserID(req, "u1")
		w := httptest.NewRecorder()
		h.ChangePassword(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: expected 400, got %d", body, w.Code)
		}
	}
}

func TestChangePasswordOIDCAccount(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: ""}, nil
		},
	}
	body := `{"currentPassword":"oldpassword123","newPassword":"newpassword456"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).ChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for OIDC account, got %d", w.Code)
	}
}

func TestChangePasswordWrongCurrentPassword(t *testing.T) {
	oldHash := hashPassword(t, "correctpassword123")
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: oldHash}, nil
		},
	}
	body := `{"currentPassword":"wrongpassword123","newPassword":"newpassword456"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).ChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestChangePasswordWeakNewPassword(t *testing.T) {
	body := `{"currentPassword":"oldpassword123","newPassword":"weak"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).ChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for weak new password, got %d", w.Code)
	}
}

func TestUpdateProfileStoreError(t *testing.T) {
	store := &mockUserStore{
		updateNameFunc: func(_ context.Context, _, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"name":"Bob"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).UpdateProfile(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestChangePasswordStoreError(t *testing.T) {
	oldHash := hashPassword(t, "oldpassword123")
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", PasswordHash: oldHash}, nil
		},
		updatePasswordFunc: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}
	body := `{"currentPassword":"oldpassword123","newPassword":"newpassword456"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).ChangePassword(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestChangePasswordFindUserError(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	body := `{"currentPassword":"oldpassword123","newPassword":"newpassword456"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).ChangePassword(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Session-enabled flows
// ---------------------------------------------------------------------------

func TestLoginCreatesSessionAndReturnsRefreshToken(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash}, nil
		},
	}
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(store, sessions)

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token when sessions enabled")
	}
}

func TestSignupCreatesSessionAndReturnsRefreshToken(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)

	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh token when sessions enabled")
	}
}

func TestSignupNoRefreshTokenWithoutSessions(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.RefreshToken != "" {
		t.Error("expected empty refresh_token when sessions not configured")
	}
}

func TestLoginSessionCreateError(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash}, nil
		},
	}
	sessions := &mockSessionStore{
		createFunc: func(_ context.Context, _, _, _, _ string, _ time.Time) (*auth.Session, error) {
			return nil, errors.New("db error")
		},
	}
	h := newAuthHandlerWithSessions(store, sessions)

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	var deletedID string
	sessions := &mockSessionStore{
		deleteFunc: func(_ context.Context, id, _ string) error {
			deletedID = id
			return nil
		},
	}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)

	// Create a token with a known session ID.
	tok, _ := h.JWT.CreateTokenWithSession(context.Background(), "u1", "sess-logout")

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if deletedID != "sess-logout" {
		t.Errorf("expected session %q to be revoked, got %q", "sess-logout", deletedID)
	}
}

func TestLogoutClearsRefreshCookie(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	h.RefreshCookieName = "refresh"

	tok, _ := h.JWT.CreateToken(context.Background(), "u1")

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: tok})
	w := httptest.NewRecorder()
	h.Logout(w, req)

	var refreshCleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "refresh" && c.MaxAge == -1 {
			refreshCleared = true
		}
	}
	if !refreshCleared {
		t.Error("expected refresh cookie to be cleared on logout")
	}
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

func TestRefreshTokenSuccess(t *testing.T) {
	rawRefresh := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	hash := auth.HashHighEntropyToken(rawRefresh)
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, h string) (*auth.Session, error) {
			if h == hash {
				return &auth.Session{ID: "sess-1", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}, nil
			}
			return nil, errors.New("not found")
		},
	}
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, Name: "Alice", Email: "alice@test.com"}, nil
		},
	}
	h := newAuthHandlerWithSessions(store, sessions)

	body := `{"refresh_token":"` + rawRefresh + `"}`
	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected new access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected new refresh token")
	}
	// New refresh token must differ from the original.
	if resp.RefreshToken == rawRefresh {
		t.Error("refresh token should be rotated")
	}
}

func TestRefreshTokenSessionsDisabled(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	w := postJSON(t, h.RefreshToken, `{"refresh_token":"anytoken"}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when sessions not configured, got %d", w.Code)
	}
}

func TestRefreshTokenMissing(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	w := postJSON(t, h.RefreshToken, `{"refresh_token":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing refresh token, got %d", w.Code)
	}
}

func TestRefreshTokenInvalidToken(t *testing.T) {
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, _ string) (*auth.Session, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	w := postJSON(t, h.RefreshToken, `{"refresh_token":"unknowntoken"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown refresh token, got %d", w.Code)
	}
}

func TestRefreshTokenExpiredSession(t *testing.T) {
	rawRefresh := "expiredtoken0011223344556677889900aabbccddeeff00112233445566778899"
	hash := auth.HashHighEntropyToken(rawRefresh)
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, h string) (*auth.Session, error) {
			if h == hash {
				return &auth.Session{ID: "sess-exp", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)}, nil
			}
			return nil, auth.ErrNotFound
		},
	}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)

	body := `{"refresh_token":"` + rawRefresh + `"}`
	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired refresh token, got %d", w.Code)
	}
}

func TestRefreshTokenFromCookie(t *testing.T) {
	rawRefresh := "cookietoken0011223344556677889900aabbccddeeff00112233445566778899"
	hash := auth.HashHighEntropyToken(rawRefresh)
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, h string) (*auth.Session, error) {
			if h == hash {
				return &auth.Session{ID: "sess-cookie", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}, nil
			}
			return nil, auth.ErrNotFound
		},
	}
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id}, nil
		},
	}
	h := newAuthHandlerWithSessions(store, sessions)
	h.RefreshCookieName = "refresh"

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh", Value: rawRefresh})
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with refresh cookie, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestRefreshTokenStoreError(t *testing.T) {
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, _ string) (*auth.Session, error) {
			return nil, errors.New("db error")
		},
	}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	w := postJSON(t, h.RefreshToken, `{"refresh_token":"anytoken"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}
