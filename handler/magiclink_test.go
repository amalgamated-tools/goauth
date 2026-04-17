package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

func newMagicLinkHandler(users auth.UserStore, links auth.MagicLinkStore, sender MagicLinkSender) *MagicLinkHandler {
	return &MagicLinkHandler{
		Users:         users,
		MagicLinks:    links,
		JWT:           newTestJWT(),
		Sender:        sender,
		CookieName:    "auth",
		SecureCookies: false,
	}
}

// noopSender is a MagicLinkSender that always succeeds without doing anything.
func noopSender(_ context.Context, _, _ string) error { return nil }

// ---------------------------------------------------------------------------
// RequestMagicLink
// ---------------------------------------------------------------------------

func TestRequestMagicLinkSuccess(t *testing.T) {
	var sentEmail, sentToken string
	sender := func(_ context.Context, email, token string) error {
		sentEmail = email
		sentToken = token
		return nil
	}
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, sender)

	w := postJSON(t, h.RequestMagicLink, `{"email":"alice@example.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if sentEmail != "alice@example.com" {
		t.Errorf("expected sender called with alice@example.com, got %q", sentEmail)
	}
	if sentToken == "" {
		t.Error("expected non-empty token passed to sender")
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] == "" {
		t.Error("expected non-empty message in response")
	}
}

func TestRequestMagicLinkMissingEmail(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	w := postJSON(t, h.RequestMagicLink, `{"email":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRequestMagicLinkEmailWhitespaceOnly(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	w := postJSON(t, h.RequestMagicLink, `{"email":"   "}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRequestMagicLinkInvalidJSON(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	w := postJSON(t, h.RequestMagicLink, "not-json")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRequestMagicLinkStoreError(t *testing.T) {
	store := &mockMagicLinkStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.MagicLink, error) {
			return nil, errors.New("db error")
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	w := postJSON(t, h.RequestMagicLink, `{"email":"alice@example.com"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRequestMagicLinkSenderErrorStillReturns200(t *testing.T) {
	sender := func(_ context.Context, _, _ string) error {
		return errors.New("smtp error")
	}
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, sender)
	w := postJSON(t, h.RequestMagicLink, `{"email":"alice@example.com"}`)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even when sender fails, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// VerifyMagicLink
// ---------------------------------------------------------------------------

func validMagicLinkStore(email string) *mockMagicLinkStore {
	return &mockMagicLinkStore{
		findAndDeleteFunc: func(_ context.Context, _ string) (*auth.MagicLink, error) {
			return &auth.MagicLink{
				ID:        "ml-1",
				Email:     email,
				ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
			}, nil
		},
	}
}

func TestVerifyMagicLinkSuccess(t *testing.T) {
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com", Name: "alice@example.com"}, nil
		},
	}
	h := newMagicLinkHandler(userStore, validMagicLinkStore("alice@example.com"), noopSender)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	var resp AuthResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty JWT token")
	}
	if resp.User.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %q", resp.User.Email)
	}
}

func TestVerifyMagicLinkSetsAuthCookie(t *testing.T) {
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com"}, nil
		},
	}
	h := newMagicLinkHandler(userStore, validMagicLinkStore("alice@example.com"), noopSender)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			found = c
		}
	}
	if found == nil || found.Value == "" {
		t.Error("expected auth cookie to be set on successful verification")
	}
}

func TestVerifyMagicLinkAutoProvision(t *testing.T) {
	var createdEmail string
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		createUserFunc: func(_ context.Context, name, email, _ string) (*auth.User, error) {
			createdEmail = email
			return &auth.User{ID: "new-id", Name: name, Email: email}, nil
		},
	}
	h := newMagicLinkHandler(userStore, validMagicLinkStore("new@example.com"), noopSender)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if createdEmail != "new@example.com" {
		t.Errorf("expected auto-provisioned user with email new@example.com, got %q", createdEmail)
	}
}

func TestVerifyMagicLinkAutoProvisionRace(t *testing.T) {
	// Simulate a race where CreateUser returns ErrEmailExists because another
	// request already created the user.
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			// First call returns not found; retry after race returns the user.
			return nil, auth.ErrNotFound
		},
		createUserFunc: func(_ context.Context, _, email, _ string) (*auth.User, error) {
			return nil, auth.ErrEmailExists
		},
	}
	// Override findByEmail so the retry succeeds.
	calls := 0
	userStore.findByEmailFunc = func(_ context.Context, email string) (*auth.User, error) {
		calls++
		if calls == 1 {
			return nil, auth.ErrNotFound
		}
		return &auth.User{ID: "race-id", Email: email}, nil
	}

	h := newMagicLinkHandler(userStore, validMagicLinkStore("race@example.com"), noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on race retry, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestVerifyMagicLinkMissingToken(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestVerifyMagicLinkInvalidToken(t *testing.T) {
	store := &mockMagicLinkStore{
		findAndDeleteFunc: func(_ context.Context, _ string) (*auth.MagicLink, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=bad", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestVerifyMagicLinkExpiredToken(t *testing.T) {
	store := &mockMagicLinkStore{
		findAndDeleteFunc: func(_ context.Context, _ string) (*auth.MagicLink, error) {
			return &auth.MagicLink{
				ID:        "ml-old",
				Email:     "alice@example.com",
				ExpiresAt: time.Now().UTC().Add(-1 * time.Minute), // already expired
			}, nil
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired token, got %d", w.Code)
	}
}

func TestVerifyMagicLinkStoreError(t *testing.T) {
	store := &mockMagicLinkStore{
		findAndDeleteFunc: func(_ context.Context, _ string) (*auth.MagicLink, error) {
			return nil, errors.New("db error")
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestVerifyMagicLinkUserStoreError(t *testing.T) {
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	h := newMagicLinkHandler(userStore, validMagicLinkStore("alice@example.com"), noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on user store error, got %d", w.Code)
	}
}
