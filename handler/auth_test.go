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
	"github.com/stretchr/testify/require"
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

func TestSignup_success(t *testing.T) {
	store := &mockUserStore{}
	h := newAuthHandler(store)

	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Token)
	require.Equal(t, "alice@test.com", resp.User.Email)
}

func TestSignup_setsAuthCookie(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	require.NotNil(t, found)
	require.NotEmpty(t, found.Value)
}

func TestSignup_disabled(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	h.DisableSignup = true
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSignup_missingName(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"","email":"a@b.com","password":"password123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignup_missingEmail(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"","password":"password123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignup_missingPassword(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"a@b.com","password":""}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignup_weakPassword(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"a@b.com","password":"short"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignup_emailConflict(t *testing.T) {
	store := &mockUserStore{
		createUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, auth.ErrEmailExists
		},
	}
	w := postJSON(t, newAuthHandler(store).Signup,
		`{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusConflict, w.Code)
}

func TestSignup_storeError(t *testing.T) {
	store := &mockUserStore{
		createUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newAuthHandler(store).Signup,
		`{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSignup_invalidJSON(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup, "not-json")
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func hashPassword(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func TestLogin_success(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"alice@test.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusOK, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Token)
}

func TestLogin_setsAuthCookie(t *testing.T) {
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
	require.NotNil(t, found)
	require.NotEmpty(t, found.Value)
}

func TestLogin_missingFields(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	for _, body := range []string{
		`{"email":"","password":"goodpassword123"}`,
		`{"email":"a@b.com","password":""}`,
	} {
		w := postJSON(t, h.Login, body)
		require.Equalf(t, http.StatusBadRequest, w.Code, "body %s", body)
	}
}

func TestLogin_userNotFound(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"nope@test.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_wrongPassword(t *testing.T) {
	hash := hashPassword(t, "correctpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "a@b.com", PasswordHash: hash}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"wrongpassword123"}`)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_oidcOnlyAccount(t *testing.T) {
	// User with no password hash (OIDC-only).
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "a@b.com", PasswordHash: ""}, nil
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_storeError(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLogin_invalidJSON(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Login, "not-json")
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

func TestLogout(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	require.NotNil(t, found)
	require.Equal(t, -1, found.MaxAge)
}

// ---------------------------------------------------------------------------
// Me
// ---------------------------------------------------------------------------

func TestMe_success(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
	var dto UserDTO
	_ = json.NewDecoder(w.Body).Decode(&dto)
	require.Equal(t, "alice@test.com", dto.Email)
}

func TestMe_notFound(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = withUserID(req, "unknown")
	w := httptest.NewRecorder()
	newAuthHandler(store).Me(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestMe_storeError(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(store).Me(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// UpdateProfile
// ---------------------------------------------------------------------------

func TestUpdateProfile_success(t *testing.T) {
	store := &mockUserStore{}
	h := newAuthHandler(store)

	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"name":"Bob"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var dto UserDTO
	_ = json.NewDecoder(w.Body).Decode(&dto)
	require.Equal(t, "Bob", dto.Name)
}

func TestUpdateProfile_emptyName(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"name":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).UpdateProfile(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProfile_invalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader("bad"))
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).UpdateProfile(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// ChangePassword
// ---------------------------------------------------------------------------

func TestChangePassword_success(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
}

func TestChangePassword_missingFields(t *testing.T) {
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
		require.Equalf(t, http.StatusBadRequest, w.Code, "body %s", body)
	}
}

func TestChangePassword_oidcAccount(t *testing.T) {
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

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangePassword_wrongCurrentPassword(t *testing.T) {
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

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestChangePassword_weakNewPassword(t *testing.T) {
	body := `{"currentPassword":"oldpassword123","newPassword":"weak"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).ChangePassword(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProfile_storeError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestChangePassword_storeError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestChangePassword_findUserError(t *testing.T) {
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Session-enabled flows
// ---------------------------------------------------------------------------

func TestLogin_createsSessionAndReturnsRefreshToken(t *testing.T) {
	hash := hashPassword(t, "goodpassword123")
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@test.com", PasswordHash: hash}, nil
		},
	}
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(store, sessions)

	w := postJSON(t, h.Login, `{"email":"alice@test.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusOK, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)
}

func TestSignup_createsSessionAndReturnsRefreshToken(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)

	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)
}

func TestSignup_noRefreshTokenWithoutSessions(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.Empty(t, resp.RefreshToken)
}

func TestLogin_sessionCreateError(t *testing.T) {
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
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLogout_revokesSession(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "sess-logout", deletedID)
}

func TestLogout_clearsRefreshCookie(t *testing.T) {
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
	require.True(t, refreshCleared)
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

func TestRefreshToken_success(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotEqual(t, rawRefresh, resp.RefreshToken)
}

func TestRefreshToken_sessionsDisabled(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	w := postJSON(t, h.RefreshToken, `{"refresh_token":"anytoken"}`)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestRefreshToken_missing(t *testing.T) {
	sessions := &mockSessionStore{}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	w := postJSON(t, h.RefreshToken, `{"refresh_token":""}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefreshToken_invalidToken(t *testing.T) {
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, _ string) (*auth.Session, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	w := postJSON(t, h.RefreshToken, `{"refresh_token":"unknowntoken"}`)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefreshToken_expiredSession(t *testing.T) {
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

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefreshToken_fromCookie(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
}

func TestRefreshToken_storeError(t *testing.T) {
	sessions := &mockSessionStore{
		findByRefreshTokenFunc: func(_ context.Context, _ string) (*auth.Session, error) {
			return nil, errors.New("db error")
		},
	}
	h := newAuthHandlerWithSessions(&mockUserStore{}, sessions)
	w := postJSON(t, h.RefreshToken, `{"refresh_token":"anytoken"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
