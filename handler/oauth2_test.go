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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockOAuth2Provider is a test double for OAuth2IdentityProvider.
type mockOAuth2Provider struct {
	fetchFunc func(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error)
}

func (m *mockOAuth2Provider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
	if m.fetchFunc != nil {
		return m.fetchFunc(ctx, token)
	}
	return &OAuth2UserInfo{
		Subject:       "github:1",
		Email:         "user@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}, nil
}

func newTestOAuth2Handler() *OAuth2Handler {
	return &OAuth2Handler{
		Users:         &mockUserStore{},
		JWT:           newTestJWT(),
		Provider:      &mockOAuth2Provider{},
		CookieName:    "auth",
		SecureCookies: false,
		LinkNonces:    &mockOIDCLinkNonceStore{},
	}
}

func newOAuth2HandlerWithConfig() *OAuth2Handler {
	h := newTestOAuth2Handler()
	h.OAuthConfig = oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/authorize",
			TokenURL: "https://example.com/token",
		},
	}
	return h
}

// injectOAuth2Code simulates the minimal OAuth2 callback by bypassing the
// real token exchange using a fake token server.
func injectOAuth2Code(t *testing.T, h *OAuth2Handler, state, code string, info *OAuth2UserInfo) *httptest.ResponseRecorder {
	t.Helper()

	// Serve a fake token endpoint.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenSrv.Close)

	h.OAuthConfig.Endpoint = oauth2.Endpoint{
		AuthURL:  "https://example.com/authorize",
		TokenURL: tokenSrv.URL,
	}

	if info != nil {
		h.Provider = &mockOAuth2Provider{
			fetchFunc: func(_ context.Context, _ *oauth2.Token) (*OAuth2UserInfo, error) {
				return info, nil
			},
		}
	}

	verifier := oauth2.GenerateVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	req := httptest.NewRequest(http.MethodGet, "/callback?state="+state+"&code="+code+"&code_challenge="+challenge, nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: state})
	req.AddCookie(&http.Cookie{Name: oauth2VerifierCookieName, Value: verifier})

	w := httptest.NewRecorder()
	h.Callback(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestOAuth2Validate_sessionWithoutRefreshCookie(t *testing.T) {
	h := newTestOAuth2Handler()
	h.Sessions = &mockSessionStore{}
	h.RefreshCookieName = ""
	require.Error(t, h.Validate())
}

func TestOAuth2Validate_sessionWithRefreshCookie(t *testing.T) {
	h := newTestOAuth2Handler()
	h.Sessions = &mockSessionStore{}
	h.RefreshCookieName = "refresh"
	require.NoError(t, h.Validate())
}

func TestOAuth2Validate_noSessions(t *testing.T) {
	h := newTestOAuth2Handler()
	require.NoError(t, h.Validate())
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func TestOAuth2Login_redirectsWithStateCookies(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.Login(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "https://example.com/authorize")

	var stateCookie, verifierCookie bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case oauth2StateCookieName:
			stateCookie = true
			require.NotEmpty(t, c.Value)
			require.True(t, c.HttpOnly)
		case oauth2VerifierCookieName:
			verifierCookie = true
			require.NotEmpty(t, c.Value)
		}
	}
	require.True(t, stateCookie, "missing oauth2_state cookie")
	require.True(t, verifierCookie, "missing oauth2_verifier cookie")
}

// ---------------------------------------------------------------------------
// Callback — early error paths
// ---------------------------------------------------------------------------

func TestOAuth2Callback_missingStateCookie(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc", nil)
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuth2Callback_stateMismatch(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=different", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: "expected"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuth2Callback_missingVerifierCookie(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: "mystate"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuth2Callback_errorParam(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&error=access_denied", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: "s"})
	req.AddCookie(&http.Cookie{Name: oauth2VerifierCookieName, Value: "v"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuth2Callback_missingCode(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=s", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: "s"})
	req.AddCookie(&http.Cookie{Name: oauth2VerifierCookieName, Value: "v"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Callback — FetchUserInfo errors
// ---------------------------------------------------------------------------

func TestOAuth2Callback_fetchUserInfoError(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenSrv.Close)
	h.OAuthConfig.Endpoint.TokenURL = tokenSrv.URL

	h.Provider = &mockOAuth2Provider{
		fetchFunc: func(_ context.Context, _ *oauth2.Token) (*OAuth2UserInfo, error) {
			return nil, errors.New("provider API error")
		},
	}

	verifier := oauth2.GenerateVerifier()
	req := httptest.NewRequest(http.MethodGet, "/callback?state=state1&code=code1", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: "state1"})
	req.AddCookie(&http.Cookie{Name: oauth2VerifierCookieName, Value: verifier})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Callback — email not verified
// ---------------------------------------------------------------------------

func TestOAuth2Callback_emailNotVerified(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	w := injectOAuth2Code(t, h, "state3", "code3", &OAuth2UserInfo{
		Subject:       "github:99",
		Email:         "unverified@example.com",
		EmailVerified: false,
	})

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Callback — new user creation
// ---------------------------------------------------------------------------

func TestOAuth2Callback_newUser(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	h.Users = &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		createOIDCUserFunc: func(_ context.Context, name, email, sub string) (*auth.User, error) {
			return &auth.User{ID: "new-user", Name: name, Email: email}, nil
		},
	}

	w := injectOAuth2Code(t, h, "state4", "code4", &OAuth2UserInfo{
		Subject:       "github:42",
		Email:         "new@example.com",
		Name:          "New User",
		EmailVerified: true,
	})

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?oauth2_login=1", w.Header().Get("Location"))
	// Auth cookie must be set.
	var authCookie bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			authCookie = true
			require.NotEmpty(t, c.Value)
		}
	}
	require.True(t, authCookie, "auth cookie not set")
}

// ---------------------------------------------------------------------------
// Callback — existing subject login
// ---------------------------------------------------------------------------

func TestOAuth2Callback_existingSubject(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	existing := &auth.User{ID: "existing-1", Email: "existing@example.com"}
	h.Users = &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
	}

	w := injectOAuth2Code(t, h, "state5", "code5", &OAuth2UserInfo{
		Subject:       "github:7",
		Email:         "existing@example.com",
		Name:          "Existing User",
		EmailVerified: true,
	})

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?oauth2_login=1", w.Header().Get("Location"))
}

// ---------------------------------------------------------------------------
// Callback — existing email match (best-effort link)
// ---------------------------------------------------------------------------

func TestOAuth2Callback_existingEmailMatch(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	existing := &auth.User{ID: "email-user", Email: "match@example.com"}
	h.Users = &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return existing, nil
		},
	}

	w := injectOAuth2Code(t, h, "state6", "code6", &OAuth2UserInfo{
		Subject:       "github:8",
		Email:         "match@example.com",
		EmailVerified: true,
	})

	require.Equal(t, http.StatusFound, w.Code)
}

// ---------------------------------------------------------------------------
// Callback — concurrent creation race (ErrEmailExists)
// ---------------------------------------------------------------------------

func TestOAuth2Callback_concurrentCreationRace(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	existing := &auth.User{ID: "race-user", Email: "race@example.com"}
	calls := 0
	h.Users = &mockUserStore{
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
	}

	w := injectOAuth2Code(t, h, "state7", "code7", &OAuth2UserInfo{
		Subject:       "github:9",
		Email:         "race@example.com",
		EmailVerified: true,
	})

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?oauth2_login=1", w.Header().Get("Location"))
}

// ---------------------------------------------------------------------------
// Callback — LoginRedirect field
// ---------------------------------------------------------------------------

func TestOAuth2Callback_customLoginRedirect(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	h.LoginRedirect = "github_login=1"
	h.Users = &mockUserStore{
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		findByEmailFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		createOIDCUserFunc: func(_ context.Context, name, email, sub string) (*auth.User, error) {
			return &auth.User{ID: "new-user", Name: name, Email: email}, nil
		},
	}

	w := injectOAuth2Code(t, h, "state8", "code8", &OAuth2UserInfo{
		Subject:       "github:10",
		Email:         "custom@example.com",
		EmailVerified: true,
	})

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?github_login=1", w.Header().Get("Location"))
}

// ---------------------------------------------------------------------------
// CreateLinkNonce
// ---------------------------------------------------------------------------

func TestOAuth2CreateLinkNonce_returnsNonce(t *testing.T) {
	h := newTestOAuth2Handler()

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-10")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	nonce := resp["nonce"]
	require.NotEmpty(t, nonce)

	// Nonce must be consumable exactly once.
	got, err := consumeLinkNonce(context.Background(), h.LinkNonces, nonce)
	require.NoError(t, err)
	require.Equal(t, "user-10", got)
}

func TestOAuth2CreateLinkNonce_nilStoreReturns503(t *testing.T) {
	h := newTestOAuth2Handler()
	h.LinkNonces = nil

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-10")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestOAuth2CreateLinkNonce_storeError(t *testing.T) {
	h := newTestOAuth2Handler()
	h.LinkNonces = &mockOIDCLinkNonceStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.OIDCLinkNonce, error) {
			return nil, errors.New("db error")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-10")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Link
// ---------------------------------------------------------------------------

func TestOAuth2Link_missingNonce(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/link", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuth2Link_invalidNonce(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/link?nonce=invalid", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuth2Link_nilStoreReturns503(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	h.LinkNonces = nil

	req := httptest.NewRequest(http.MethodGet, "/link?nonce=test", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestOAuth2Link_alreadyLinked(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	nonce := "test-link-nonce"
	_, err := h.LinkNonces.CreateLinkNonce(context.Background(), "user-1", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

	sub := "github:existing"
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

func TestOAuth2Link_userNotFound(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	nonce := "notfound-nonce"
	_, err := h.LinkNonces.CreateLinkNonce(context.Background(), "missing-user", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

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

func TestOAuth2Link_userStoreError(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	nonce := "user-store-error-nonce"
	_, err := h.LinkNonces.CreateLinkNonce(context.Background(), "user-1", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, errors.New("transient store error")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestOAuth2Link_nonceStoreError(t *testing.T) {
	h := newOAuth2HandlerWithConfig()
	h.LinkNonces = &mockOIDCLinkNonceStore{
		consumeAndDeleteFunc: func(_ context.Context, _ string) (*auth.OIDCLinkNonce, error) {
			return nil, errors.New("db error")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link?nonce=some-nonce", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestOAuth2Link_success(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	nonce := "success-link-nonce"
	_, err := h.LinkNonces.CreateLinkNonce(context.Background(), "user-ok", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: nil}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	// Should redirect to the OAuth2 provider.
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "https://example.com/authorize")
}

// ---------------------------------------------------------------------------
// Callback — link flow (link callback via signed state)
// ---------------------------------------------------------------------------

func TestOAuth2Callback_linkFlow_success(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	linkUserID := "user-to-link"
	randomState := "randomstate123"
	signedState := signLinkState(h.JWT, randomState, linkUserID)

	linkedSubject := ""
	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: nil}, nil
		},
		findByOIDCSubjectFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, auth.ErrNotFound
		},
		linkOIDCSubjectFunc: func(_ context.Context, _, sub string) error {
			linkedSubject = sub
			return nil
		},
	}

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenSrv.Close)
	h.OAuthConfig.Endpoint.TokenURL = tokenSrv.URL

	h.Provider = &mockOAuth2Provider{
		fetchFunc: func(_ context.Context, _ *oauth2.Token) (*OAuth2UserInfo, error) {
			return &OAuth2UserInfo{
				Subject:       "github:55",
				Email:         "link@example.com",
				EmailVerified: true,
			}, nil
		},
	}

	verifier := oauth2.GenerateVerifier()
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+signedState+"&code=linkcode", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: signedState})
	req.AddCookie(&http.Cookie{Name: oauth2VerifierCookieName, Value: verifier})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?oauth2_linked=true", w.Header().Get("Location"))
	require.Equal(t, "github:55", linkedSubject)
}

func TestOAuth2Callback_linkFlow_alreadyLinked(t *testing.T) {
	h := newOAuth2HandlerWithConfig()

	linkUserID := "user-already-linked"
	randomState := "randomstate456"
	signedState := signLinkState(h.JWT, randomState, linkUserID)

	existingSub := "github:old"
	h.Users = &mockUserStore{
		findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
			return &auth.User{ID: id, OIDCSubject: &existingSub}, nil
		},
	}

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(tokenSrv.Close)
	h.OAuthConfig.Endpoint.TokenURL = tokenSrv.URL

	h.Provider = &mockOAuth2Provider{
		fetchFunc: func(_ context.Context, _ *oauth2.Token) (*OAuth2UserInfo, error) {
			return &OAuth2UserInfo{
				Subject:       "github:99",
				Email:         "link@example.com",
				EmailVerified: true,
			}, nil
		},
	}

	verifier := oauth2.GenerateVerifier()
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+signedState+"&code=c2", nil)
	req.AddCookie(&http.Cookie{Name: oauth2StateCookieName, Value: signedState})
	req.AddCookie(&http.Cookie{Name: oauth2VerifierCookieName, Value: verifier})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "oauth2_link_error=")
	require.Contains(t, loc, "Already+linked")
}
