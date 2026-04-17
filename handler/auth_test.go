package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestSignupSuccess(t *testing.T) {
	store := &mockUserStore{}
	h := newAuthHandler(store)

	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	require.NotEmpty(t, resp.Token)
	require.Equal(t, "alice@test.com", resp.User.Email)
}

func TestSignupSetsAuthCookie(t *testing.T) {
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

func TestSignupDisabled(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	h.DisableSignup = true
	w := postJSON(t, h.Signup, `{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSignupMissingName(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"","email":"a@b.com","password":"password123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupMissingEmail(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"","password":"password123"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupMissingPassword(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"a@b.com","password":""}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupWeakPassword(t *testing.T) {
	w := postJSON(t, newAuthHandler(&mockUserStore{}).Signup,
		`{"name":"Alice","email":"a@b.com","password":"short"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupEmailConflict(t *testing.T) {
	store := &mockUserStore{
		createUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, auth.ErrEmailExists
		},
	}
	w := postJSON(t, newAuthHandler(store).Signup,
		`{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusConflict, w.Code)
}

func TestSignupStoreError(t *testing.T) {
	store := &mockUserStore{
		createUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newAuthHandler(store).Signup,
		`{"name":"Alice","email":"alice@test.com","password":"password123"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSignupInvalidJSON(t *testing.T) {
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

func TestLoginSuccess(t *testing.T) {
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
	require.NotNil(t, found)
	require.NotEmpty(t, found.Value)
}

func TestLoginMissingFields(t *testing.T) {
	h := newAuthHandler(&mockUserStore{})
	for _, body := range []string{
		`{"email":"","password":"goodpassword123"}`,
		`{"email":"a@b.com","password":""}`,
	} {
		w := postJSON(t, h.Login, body)
		require.Equalf(t, http.StatusBadRequest, w.Code, "body %s", body)
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
	require.Equal(t, http.StatusUnauthorized, w.Code)
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
	require.Equal(t, http.StatusUnauthorized, w.Code)
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
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLoginStoreError(t *testing.T) {
	store := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	w := postJSON(t, newAuthHandler(store).Login,
		`{"email":"a@b.com","password":"goodpassword123"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLoginInvalidJSON(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
	var dto UserDTO
	_ = json.NewDecoder(w.Body).Decode(&dto)
	require.Equal(t, "alice@test.com", dto.Email)
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

	require.Equal(t, http.StatusNotFound, w.Code)
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
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

	require.Equal(t, http.StatusOK, w.Code)
	var dto UserDTO
	_ = json.NewDecoder(w.Body).Decode(&dto)
	require.Equal(t, "Bob", dto.Name)
}

func TestUpdateProfileEmptyName(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"name":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).UpdateProfile(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProfileInvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader("bad"))
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).UpdateProfile(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
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

	require.Equal(t, http.StatusOK, w.Code)
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
		require.Equalf(t, http.StatusBadRequest, w.Code, "body %s", body)
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

	require.Equal(t, http.StatusBadRequest, w.Code)
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

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestChangePasswordWeakNewPassword(t *testing.T) {
	body := `{"currentPassword":"oldpassword123","newPassword":"weak"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserID(req, "u1")
	w := httptest.NewRecorder()
	newAuthHandler(&mockUserStore{}).ChangePassword(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
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

	require.Equal(t, http.StatusInternalServerError, w.Code)
}
