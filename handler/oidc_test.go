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
	"golang.org/x/oauth2"
)

func newTestOIDCHandler() *OIDCHandler {
	return &OIDCHandler{
		Users:         &mockUserStore{},
		JWT:           newTestJWT(),
		CookieName:    "auth",
		SecureCookies: false,
		linkNonces:    make(map[string]linkNonce),
	}
}

// ---------------------------------------------------------------------------
// signLinkState / parseLinkState
// ---------------------------------------------------------------------------

func TestLinkState_roundTrip(t *testing.T) {
	h := newTestOIDCHandler()

	randomState := "somerandomstate1234"
	userID := "user-abc"

	signed := h.signLinkState(randomState, userID)
	require.NotEmpty(t, signed)

	parsed := h.parseLinkState(signed)
	require.Equal(t, userID, parsed)
}

func TestParseLinkState_invalidFormat(t *testing.T) {
	h := newTestOIDCHandler()

	// Not enough parts.
	for _, bad := range []string{
		"",
		"only-one-part",
		"two.parts",
	} {
		require.Emptyf(t, h.parseLinkState(bad), "input %q", bad)
	}
}

func TestParseLinkState_tamperedSignature(t *testing.T) {
	h := newTestOIDCHandler()

	signed := h.signLinkState("randomstate", "user-1")
	// Corrupt the last character of the signature (third dot-separated part).
	tampered := signed[:len(signed)-1] + "X"
	require.Empty(t, h.parseLinkState(tampered))
}

func TestParseLinkState_wrongKey(t *testing.T) {
	h1 := newTestOIDCHandler()
	h2 := &OIDCHandler{
		JWT:        newTestJWT(), // same secret, different derived key...
		linkNonces: make(map[string]linkNonce),
	}
	// Give h2 a different JWT manager (different secret).
	mgr2, _ := auth.NewJWTManager("different-secret-32bytes-here!!!!", time.Hour, "test")
	h2.JWT = mgr2

	signed := h1.signLinkState("state123", "user-xyz")
	require.Empty(t, h2.parseLinkState(signed))
}

// ---------------------------------------------------------------------------
// consumeLinkNonce / CreateLinkNonce
// ---------------------------------------------------------------------------

func TestConsumeLinkNonce_deletesEntry(t *testing.T) {
	h := newTestOIDCHandler()

	nonce := "test-nonce-123"
	h.linkNonces[nonce] = linkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(time.Minute)}

	got := h.consumeLinkNonce(nonce)
	require.Equal(t, "user-1", got)

	// Second consumption of the same nonce should return empty.
	require.Empty(t, h.consumeLinkNonce(nonce))
}

func TestConsumeLinkNonce_expired(t *testing.T) {
	h := newTestOIDCHandler()

	nonce := "expired-nonce"
	h.linkNonces[nonce] = linkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(-time.Second)}

	require.Empty(t, h.consumeLinkNonce(nonce))
}

func TestConsumeLinkNonce_notFound(t *testing.T) {
	h := newTestOIDCHandler()
	require.Empty(t, h.consumeLinkNonce("does-not-exist"))
}

func TestCreateLinkNonce_returnsNonce(t *testing.T) {
	h := newTestOIDCHandler()

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-42")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	nonce := resp["nonce"]
	require.NotEmpty(t, nonce)

	// The nonce should be consumable.
	got := h.consumeLinkNonce(nonce)
	require.Equal(t, "user-42", got)
}

func TestCreateLinkNonce_cleansUpExpiredEntries(t *testing.T) {
	h := newTestOIDCHandler()

	// Pre-populate with an expired entry.
	h.linkNonces["old-nonce"] = linkNonce{UserID: "old-user", ExpiresAt: time.Now().Add(-time.Minute)}

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-42")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	h.linkNoncesMu.Lock()
	_, exists := h.linkNonces["old-nonce"]
	h.linkNoncesMu.Unlock()
	require.False(t, exists)
}

// ---------------------------------------------------------------------------
// findOrCreateUser
// ---------------------------------------------------------------------------

func TestFindOrCreateUser_byOIDCSubject(t *testing.T) {
	existing := &auth.User{ID: "u1", Email: "a@b.com"}
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub1", "a@b.com", "Alice")
	require.NoError(t, err)
	require.Equal(t, "u1", user.ID)
}

func TestFindOrCreateUser_byEmail(t *testing.T) {
	existing := &auth.User{ID: "u2", Email: "b@c.com"}
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub2", "b@c.com", "Bob")
	require.NoError(t, err)
	require.Equal(t, "u2", user.ID)
}

func TestFindOrCreateUser_byEmailLinkError(t *testing.T) {
	// When LinkOIDCSubject returns an unexpected error, findOrCreateUser should
	// still succeed (returning the email-matched user) and not surface the link
	// failure to the caller.
	existing := &auth.User{ID: "u3", Email: "c@d.com"}
	linkErr := errors.New("db connection lost")
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
		linkOIDCSubjectFunc: func(_ context.Context, _, _ string) error {
			return linkErr
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub3", "c@d.com", "Carol")
	require.NoError(t, err)
	require.Equal(t, "u3", user.ID)
}

func TestFindOrCreateUser_byEmailAlreadyLinked(t *testing.T) {
	// ErrOIDCSubjectAlreadyLinked should be treated as a benign no-op.
	existing := &auth.User{ID: "u4", Email: "d@e.com"}
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
		linkOIDCSubjectFunc: func(_ context.Context, _, _ string) error {
			return auth.ErrOIDCSubjectAlreadyLinked
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub4", "d@e.com", "Dave")
	require.NoError(t, err)
	require.Equal(t, "u4", user.ID)
}

func TestFindOrCreateUser_raceRetryLinkError(t *testing.T) {
	// The race-retry email-match path (lines ~230-234) should also swallow link
	// errors and still return the found user.
	existing := &auth.User{ID: "u5", Email: "e@f.com"}
	linkErr := errors.New("db timeout")
	calls := 0
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			calls++
			if calls == 1 {
				return nil, auth.ErrNotFound
			}
			return existing, nil
		},
		createOIDCUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, auth.ErrEmailExists
		},
		linkOIDCSubjectFunc: func(_ context.Context, _, _ string) error {
			return linkErr
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub5", "e@f.com", "Eve")
	require.NoError(t, err)
	require.Equal(t, "u5", user.ID)
}

func TestFindOrCreateUser_raceRetryAlreadyLinked(t *testing.T) {
	// ErrOIDCSubjectAlreadyLinked on the race-retry path should also be a benign no-op.
	existing := &auth.User{ID: "u6", Email: "f@g.com"}
	calls := 0
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			calls++
			if calls == 1 {
				return nil, auth.ErrNotFound
			}
			return existing, nil
		},
		createOIDCUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, auth.ErrEmailExists
		},
		linkOIDCSubjectFunc: func(_ context.Context, _, _ string) error {
			return auth.ErrOIDCSubjectAlreadyLinked
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub6", "f@g.com", "Frank")
	require.NoError(t, err)
	require.Equal(t, "u6", user.ID)
}

func TestFindOrCreateUser_createsNew(t *testing.T) {
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		createOIDCUserFunc: func(_ context.Context, name, email, sub string) (*auth.User, error) {
			return &auth.User{ID: "new-u", Name: name, Email: email}, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub-new", "new@example.com", "New User")
	require.NoError(t, err)
	require.Equal(t, "new-u", user.ID)
}

func TestFindOrCreateUser_createError(t *testing.T) {
	// A non-race DB error from CreateOIDCUser must be returned immediately,
	// not silently swallowed by the race-retry block.
	dbErr := errors.New("connection reset by peer")
	store := &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		createOIDCUserFunc: func(_ context.Context, _, _, _ string) (*auth.User, error) {
			return nil, dbErr
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	user, err := h.findOrCreateUser(context.Background(), "sub-err", "err@example.com", "Err User")
	require.Error(t, err)
	require.ErrorIs(t, err, dbErr)
	require.Nil(t, user)
}

// ---------------------------------------------------------------------------
// handleLinkCallback
// ---------------------------------------------------------------------------

func TestHandleLinkCallback_success(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: nil}, nil
		},
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "user-1", "oidc-sub")

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?oidc_linked=true", w.Header().Get("Location"))
}

func TestHandleLinkCallback_userNotFound(t *testing.T) {
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "missing-user", "oidc-sub")

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.NotEqual(t, "/?oidc_linked=true", loc)
}

func TestHandleLinkCallback_dbErrorOnFindByOIDCSubject(t *testing.T) {
	dbErr := errors.New("connection timeout")
	linkCalled := false
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: nil}, nil
		},
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, dbErr
		},
		linkOIDCSubjectFunc: func(_ context.Context, _, _ string) error {
			linkCalled = true
			return nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "user-1", "oidc-sub")

	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "oidc_link_error=")
	require.Contains(t, w.Header().Get("Location"), "Link+verification+failed")
	require.False(t, linkCalled, "LinkOIDCSubject must not be called on DB error")
}

func TestHandleLinkCallback_alreadyLinked(t *testing.T) {
	sub := "existing-sub"
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: &sub}, nil
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.handleLinkCallback(w, req, "user-1", "other-sub")

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.NotEqual(t, "/?oidc_linked=true", loc)
}

// ---------------------------------------------------------------------------
// Login handler
// ---------------------------------------------------------------------------

func newOIDCHandlerWithConfig() *OIDCHandler {
	h := newTestOIDCHandler()
	h.OAuthConfig = oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/authorize",
			TokenURL: "https://example.com/token",
		},
		Scopes: []string{"openid", "email", "profile"},
	}
	return h
}

func TestOIDCLogin_redirectsWithStateCookies(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.Login(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	// Must redirect to the provider.
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "https://example.com/authorize")

	// Must set both OIDC state and verifier cookies.
	var stateCookie, verifierCookie bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case oidcStateCookieName:
			stateCookie = true
			require.NotEmpty(t, c.Value)
			require.True(t, c.HttpOnly)
		case oidcVerifierCookieName:
			verifierCookie = true
			require.NotEmpty(t, c.Value)
		}
	}
	require.True(t, stateCookie, "missing oidc_state cookie")
	require.True(t, verifierCookie, "missing oidc_verifier cookie")
}

// ---------------------------------------------------------------------------
// Link handler
// ---------------------------------------------------------------------------

func TestOIDCLink_missingNonce(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/link", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCLink_invalidNonce(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/link?nonce=invalid-nonce", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOIDCLink_alreadyLinked(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	// Create a valid nonce for user-1.
	nonce := "test-link-nonce"
	h.linkNonces[nonce] = linkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(time.Minute)}

	// User already has an OIDC subject linked.
	sub := "existing-sub"
	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: &sub}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusConflict, w.Code)
}

func TestOIDCLink_userNotFound(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	nonce := "notfound-nonce"
	h.linkNonces[nonce] = linkNonce{UserID: "missing-user", ExpiresAt: time.Now().Add(time.Minute)}

	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusConflict, w.Code)
}

func TestOIDCLink_success(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	nonce := "success-link-nonce"
	h.linkNonces[nonce] = linkNonce{UserID: "user-ok", ExpiresAt: time.Now().Add(time.Minute)}

	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			// User exists and has no OIDC subject yet.
			return &auth.User{ID: id, OIDCSubject: nil}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	// Should redirect to the OIDC provider for authentication.
	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "https://example.com/authorize")
}

// ---------------------------------------------------------------------------
// Callback handler — early error paths (no real OIDC exchange needed)
// ---------------------------------------------------------------------------

func TestOIDCCallback_missingStateCookie(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc", nil)
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_stateMismatch(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=different", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "expected-state"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_missingVerifierCookie(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	// verifier cookie intentionally omitted
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_errorParam(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate&error=access_denied", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOIDCCallback_missingCode(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_sessionsWithoutRefreshCookieName_returnsError(t *testing.T) {
	h := newTestOIDCHandler()
	h.Sessions = &mockSessionStore{}
	// h.RefreshCookieName is "" (zero value)

	require.Error(t, h.Validate())
}

func TestValidate_sessionsWithRefreshCookieName_ok(t *testing.T) {
	h := newTestOIDCHandler()
	h.Sessions = &mockSessionStore{}
	h.RefreshCookieName = "refresh"

	require.NoError(t, h.Validate())
}

func TestValidate_noSessions_ok(t *testing.T) {
	h := newTestOIDCHandler()
	// Sessions is nil — RefreshCookieName is not required.
	require.NoError(t, h.Validate())
}
