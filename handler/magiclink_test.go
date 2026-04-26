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
	"github.com/stretchr/testify/require"
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

func newMagicLinkHandlerWithSessions(users auth.UserStore, links auth.MagicLinkStore, sessions auth.SessionStore) *MagicLinkHandler {
	return &MagicLinkHandler{
		Users:             users,
		MagicLinks:        links,
		JWT:               newTestJWT(),
		Sessions:          sessions,
		Sender:            noopSender,
		CookieName:        "auth",
		RefreshCookieName: "refresh",
		SecureCookies:     false,
	}
}

// noopSender is a MagicLinkSender that always succeeds without doing anything.
func noopSender(_ context.Context, _, _ string) error { return nil }

// ---------------------------------------------------------------------------
// RequestMagicLink
// ---------------------------------------------------------------------------

func TestRequestMagicLink_success(t *testing.T) {
	var sentEmail, sentToken string
	sender := func(_ context.Context, email, token string) error {
		sentEmail = email
		sentToken = token
		return nil
	}
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, sender)

	w := postJSON(t, h.RequestMagicLink, `{"email":"alice@example.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "alice@example.com", sentEmail)
	require.NotEmpty(t, sentToken)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp["message"])
}

func TestRequestMagicLink_missingEmail(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	w := postJSON(t, h.RequestMagicLink, `{"email":""}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequestMagicLink_emailWhitespaceOnly(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	w := postJSON(t, h.RequestMagicLink, `{"email":"   "}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequestMagicLink_invalidJSON(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	w := postJSON(t, h.RequestMagicLink, "not-json")
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequestMagicLink_storeError(t *testing.T) {
	store := &mockMagicLinkStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.MagicLink, error) {
			return nil, errors.New("db error")
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	w := postJSON(t, h.RequestMagicLink, `{"email":"alice@example.com"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequestMagicLink_senderErrorStillReturns200(t *testing.T) {
	sender := func(_ context.Context, _, _ string) error {
		return errors.New("smtp error")
	}
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, sender)
	w := postJSON(t, h.RequestMagicLink, `{"email":"alice@example.com"}`)
	require.Equal(t, http.StatusOK, w.Code)
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

func TestVerifyMagicLink_success(t *testing.T) {
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com", Name: "alice@example.com"}, nil
		},
	}
	h := newMagicLinkHandler(userStore, validMagicLinkStore("alice@example.com"), noopSender)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp AuthResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp.Token)
	require.Equal(t, "alice@example.com", resp.User.Email)
}

func TestVerifyMagicLink_setsAuthCookie(t *testing.T) {
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
	require.NotNil(t, found)
	require.NotEmpty(t, found.Value)
}

func TestVerifyMagicLink_autoProvision(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "new@example.com", createdEmail)
}

func TestVerifyMagicLink_autoProvisionRace(t *testing.T) {
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

	require.Equal(t, http.StatusOK, w.Code)
}

func TestVerifyMagicLink_missingToken(t *testing.T) {
	h := newMagicLinkHandler(&mockUserStore{}, &mockMagicLinkStore{}, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyMagicLink_invalidToken(t *testing.T) {
	store := &mockMagicLinkStore{
		findAndDeleteFunc: func(_ context.Context, _ string) (*auth.MagicLink, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=bad", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyMagicLink_expiredToken(t *testing.T) {
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
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyMagicLink_storeError(t *testing.T) {
	store := &mockMagicLinkStore{
		findAndDeleteFunc: func(_ context.Context, _ string) (*auth.MagicLink, error) {
			return nil, errors.New("db error")
		},
	}
	h := newMagicLinkHandler(&mockUserStore{}, store, noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestVerifyMagicLink_userStoreError(t *testing.T) {
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("db error")
		},
	}
	h := newMagicLinkHandler(userStore, validMagicLinkStore("alice@example.com"), noopSender)
	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// VerifyMagicLink with session tracking
// ---------------------------------------------------------------------------

func TestVerifyMagicLinkWithSessionsCreatesSession(t *testing.T) {
	var capturedUserID string
	sessions := &mockSessionStore{
		createFunc: func(_ context.Context, userID, _, _, _ string, _ time.Time) (*auth.Session, error) {
			capturedUserID = userID
			return &auth.Session{ID: "sess-1", UserID: userID}, nil
		},
	}
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com", Name: "Alice"}, nil
		},
	}
	h := newMagicLinkHandlerWithSessions(userStore, validMagicLinkStore("alice@example.com"), sessions)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "u1", capturedUserID)
	var resp AuthResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)
}

func TestVerifyMagicLinkWithSessionsSetsRefreshCookie(t *testing.T) {
	sessions := &mockSessionStore{}
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com"}, nil
		},
	}
	h := newMagicLinkHandlerWithSessions(userStore, validMagicLinkStore("alice@example.com"), sessions)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var foundRefresh *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "refresh" {
			foundRefresh = c
		}
	}
	require.NotNil(t, foundRefresh)
	require.NotEmpty(t, foundRefresh.Value)
}

func TestVerifyMagicLinkWithSessionsCreateSessionError(t *testing.T) {
	sessions := &mockSessionStore{
		createFunc: func(_ context.Context, _, _, _, _ string, _ time.Time) (*auth.Session, error) {
			return nil, errors.New("db error")
		},
	}
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com"}, nil
		},
	}
	h := newMagicLinkHandlerWithSessions(userStore, validMagicLinkStore("alice@example.com"), sessions)

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestVerifyMagicLinkWithSessionsCreateTokenError(t *testing.T) {
	var deletedSessionID string
	sessions := &mockSessionStore{
		createFunc: func(_ context.Context, userID, _, _, _ string, _ time.Time) (*auth.Session, error) {
			return &auth.Session{ID: "sess-orphan", UserID: userID}, nil
		},
		deleteFunc: func(_ context.Context, id, _ string) error {
			deletedSessionID = id
			return nil
		},
	}
	userStore := &mockUserStore{
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return &auth.User{ID: "u1", Email: "alice@example.com"}, nil
		},
	}
	h := newMagicLinkHandlerWithSessions(userStore, validMagicLinkStore("alice@example.com"), sessions)
	h.JWT = &mockTokenCreator{
		createTokenWithSessionFunc: func(_ context.Context, _, _ string) (string, error) {
			return "", errors.New("jwt signing error")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify?token=sometoken", nil)
	w := httptest.NewRecorder()
	h.VerifyMagicLink(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Equal(t, "sess-orphan", deletedSessionID, "orphaned session must be cleaned up")
}
