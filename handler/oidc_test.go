package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/coreos/go-oidc/v3/oidc"
	// go-jose is used to construct cryptographically-valid RS256 id_tokens for fake OIDC providers in tests.
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newTestOIDCHandler() *OIDCHandler {
	return &OIDCHandler{
		Users:         &mockUserStore{},
		JWT:           newTestJWT(),
		CookieName:    "auth",
		SecureCookies: false,
		LinkNonces:    &mockOIDCLinkNonceStore{},
	}
}

// newMockOIDCProvider creates a real *oidc.Provider backed by a local httptest
// server that serves a minimal OpenID Connect discovery document.
func newMockOIDCProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srvURL, srvURL+"/auth", srvURL+"/token", srvURL+"/keys")
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL
	p, err := oidc.NewProvider(context.Background(), srv.URL)
	require.NoError(t, err)
	return p
}

// newSignedOIDCProvider starts a local httptest OIDC provider serving discovery,
// JWKS, and token endpoints. jwksKey.PublicKey is published in the JWKS; signingKey
// is used to sign the id_token. Pass the same key for both to produce a
// cryptographically-valid token; pass different keys to simulate a key-mismatch
// scenario. The "iss" claim is automatically set to the server URL when not present
// in claims. The server is stopped automatically via t.Cleanup.
func newSignedOIDCProvider(t *testing.T, jwksKey, signingKey *rsa.PrivateKey, claims map[string]any) (providerURL, idToken string) {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	providerURL = srv.URL

	jwk := jose.JSONWebKey{Key: &jwksKey.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	jwksBytes, err := json.Marshal(struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}{Keys: []jose.JSONWebKey{jwk}})
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, providerURL, providerURL+"/auth", providerURL+"/token", providerURL+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})

	// Merge caller-supplied claims; inject "iss" when absent so the token is
	// accepted by the go-oidc issuer check.
	merged := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		merged[k] = v
	}
	if _, ok := merged["iss"]; !ok {
		merged["iss"] = providerURL
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key"),
	)
	require.NoError(t, err)
	idToken, err = josejwt.Signed(signer).Claims(merged).Serialize()
	require.NoError(t, err)

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"tok","token_type":"bearer","id_token":%q}`, idToken)
	})

	return providerURL, idToken
}

// ---------------------------------------------------------------------------
// signLinkState / parseLinkState
// ---------------------------------------------------------------------------

func TestLinkState_roundTrip(t *testing.T) {
	h := newTestOIDCHandler()

	randomState := "somerandomstate1234"
	userID := "user-abc"

	signed := signLinkState(h.JWT, randomState, userID)
	require.NotEmpty(t, signed)

	parsed := parseLinkState(h.JWT, signed)
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
		require.Emptyf(t, parseLinkState(h.JWT, bad), "input %q", bad)
	}
}

func TestParseLinkState_tamperedSignature(t *testing.T) {
	h := newTestOIDCHandler()

	signed := signLinkState(h.JWT, "randomstate", "user-1")
	// Corrupt the last character of the signature (third dot-separated part).
	tampered := signed[:len(signed)-1] + "X"
	require.Empty(t, parseLinkState(h.JWT, tampered))
}

func TestParseLinkState_wrongKey(t *testing.T) {
	h1 := newTestOIDCHandler()
	h2 := &OIDCHandler{
		JWT: newTestJWT(), // same secret, different derived key...
	}
	// Give h2 a different JWT manager (different secret).
	mgr2, _ := auth.NewJWTManager("different-secret-32bytes-here!!!!", time.Hour, "test")
	h2.JWT = mgr2

	signed := signLinkState(h1.JWT, "state123", "user-xyz")
	require.Empty(t, parseLinkState(h2.JWT, signed))
}

// ---------------------------------------------------------------------------
// consumeLinkNonce / CreateLinkNonce
// ---------------------------------------------------------------------------

func TestConsumeLinkNonce_deletesEntry(t *testing.T) {
	h := newTestOIDCHandler()

	nonce := "test-nonce-123"
	nonceHash := auth.HashHighEntropyToken(nonce)
	consumed := false
	h.LinkNonces = &mockOIDCLinkNonceStore{
		consumeAndDeleteFunc: func(_ context.Context, hash string) (*auth.OIDCLinkNonce, error) {
			if consumed || hash != nonceHash {
				return nil, auth.ErrNotFound
			}
			consumed = true
			return &auth.OIDCLinkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(time.Minute)}, nil
		},
	}

	got, err := consumeLinkNonce(context.Background(), h.LinkNonces, nonce)
	require.NoError(t, err)
	require.Equal(t, "user-1", got)

	// Second consumption of the same nonce should return ErrNotFound.
	_, err = consumeLinkNonce(context.Background(), h.LinkNonces, nonce)
	require.ErrorIs(t, err, auth.ErrNotFound)
}

func TestConsumeLinkNonce_expired(t *testing.T) {
	h := newTestOIDCHandler()

	nonce := "expired-nonce"
	h.LinkNonces = &mockOIDCLinkNonceStore{
		consumeAndDeleteFunc: func(_ context.Context, _ string) (*auth.OIDCLinkNonce, error) {
			return &auth.OIDCLinkNonce{UserID: "user-1", ExpiresAt: time.Now().Add(-time.Second)}, nil
		},
	}

	_, err := consumeLinkNonce(context.Background(), h.LinkNonces, nonce)
	require.ErrorIs(t, err, auth.ErrNotFound)
}

func TestConsumeLinkNonce_notFound(t *testing.T) {
	h := newTestOIDCHandler()
	_, err := consumeLinkNonce(context.Background(), h.LinkNonces, "does-not-exist")
	require.ErrorIs(t, err, auth.ErrNotFound)
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

	// The nonce should be consumable exactly once.
	got, err := consumeLinkNonce(context.Background(), h.LinkNonces, nonce)
	require.NoError(t, err)
	require.Equal(t, "user-42", got)
}

func TestCreateLinkNonce_nilStoreReturns503(t *testing.T) {
	h := newTestOIDCHandler()
	h.LinkNonces = nil

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-42")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCreateLinkNonce_storeError(t *testing.T) {
	h := newTestOIDCHandler()
	h.LinkNonces = &mockOIDCLinkNonceStore{
		createFunc: func(_ context.Context, _, _ string, _ time.Time) (*auth.OIDCLinkNonce, error) {
			return nil, errors.New("db error")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/link-nonce", nil)
	req = withUserID(req, "user-42")
	w := httptest.NewRecorder()
	h.CreateLinkNonce(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub1", "a@b.com", "Alice")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub2", "b@c.com", "Bob")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub3", "c@d.com", "Carol")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub4", "d@e.com", "Dave")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub5", "e@f.com", "Eve")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub6", "f@g.com", "Frank")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub-new", "new@example.com", "New User")
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

	user, err := findOrCreateUser(context.Background(), nil, h.Users, "sub-err", "err@example.com", "Err User")
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
	handleLinkCallback(w, req, nil, h.Users, "user-1", "oidc-sub", "/?oidc_linked=true", "oidc_link_error")

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
	handleLinkCallback(w, req, nil, h.Users, "missing-user", "oidc-sub", "/?oidc_linked=true", "oidc_link_error")

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.NotEqual(t, "/?oidc_linked=true", loc)
}

func TestHandleLinkCallback_dbErrorOnFindByID(t *testing.T) {
	dbErr := errors.New("connection timeout")
	store := &mockUserStore{
		findByIDFunc: func(_ context.Context, _ string) (*auth.User, error) {
			return nil, dbErr
		},
	}
	h := newTestOIDCHandler()
	h.Users = store

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handleLinkCallback(w, req, nil, h.Users, "user-1", "oidc-sub", "/?oidc_linked=true", "oidc_link_error")

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "oidc_link_error=")
	require.Contains(t, loc, "Link+verification+failed")
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
	handleLinkCallback(w, req, nil, h.Users, "user-1", "oidc-sub", "/?oidc_linked=true", "oidc_link_error")

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
	handleLinkCallback(w, req, nil, h.Users, "user-1", "other-sub", "/?oidc_linked=true", "oidc_link_error")

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

func TestOIDCLogin_redirectsWithOIDCFlowCookies(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.Login(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	// Must redirect to the provider.
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "https://example.com/authorize")

	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Query().Get("nonce"))

	// Must set OIDC state, verifier, and nonce cookies.
	var stateCookie, verifierCookie, nonceCookie bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case oidcStateCookieName:
			stateCookie = true
			require.NotEmpty(t, c.Value)
			require.True(t, c.HttpOnly)
		case oidcVerifierCookieName:
			verifierCookie = true
			require.NotEmpty(t, c.Value)
		case oidcNonceCookieName:
			nonceCookie = true
			require.NotEmpty(t, c.Value)
		}
	}
	require.True(t, stateCookie, "missing oidc_state cookie")
	require.True(t, verifierCookie, "missing oidc_verifier cookie")
	require.True(t, nonceCookie, "missing oidc_nonce cookie")
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
	_, err := h.LinkNonces.CreateLinkNonce(context.Background(), "user-1", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

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

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestOIDCLink_dbErrorOnFindByID(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	nonce := "store-error-nonce"
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

func TestOIDCLink_success(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	nonce := "success-link-nonce"
	_, err := h.LinkNonces.CreateLinkNonce(context.Background(), "user-ok", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

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

func TestOIDCLink_nilStoreReturns503(t *testing.T) {
	h := newOIDCHandlerWithConfig()
	h.LinkNonces = nil

	req := httptest.NewRequest(http.MethodGet, "/link?nonce=test", nil)
	w := httptest.NewRecorder()
	h.Link(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestOIDCLink_storeError(t *testing.T) {
	h := newOIDCHandlerWithConfig()
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

func TestOIDCCallback_missingNonceCookie(t *testing.T) {
	h := newOIDCHandlerWithConfig()

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate&code=authcode", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_nonceMismatch(t *testing.T) {
	// Build a fake OIDC provider that returns a valid id_token with a known nonce
	// that differs from the cookie value, exercising the nonce mismatch branch.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	providerURL, _ := newSignedOIDCProvider(t, key, key, map[string]any{
		"sub":   "user-123",
		"aud":   "test-client",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "wrong-nonce",
	})

	provider, err := oidc.NewProvider(context.Background(), providerURL)
	require.NoError(t, err)

	h := newTestOIDCHandler()
	h.Provider = provider
	h.OAuthConfig = oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   providerURL + "/auth",
			TokenURL:  providerURL + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
	require.NoError(t, h.Validate())

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate&code=authcode", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	req.AddCookie(&http.Cookie{Name: oidcNonceCookieName, Value: "correct-nonce"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid nonce")
}

func TestOIDCCallback_wrongSigningKey(t *testing.T) {
	// keyA is published in the JWKS; keyB signs the id_token.
	// go-oidc must reject the token because its signature cannot be verified
	// against any key in the JWKS, exercising the cryptographic-mismatch path.
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	providerURL, _ := newSignedOIDCProvider(t, keyA, keyB, map[string]any{
		"sub": "user-123",
		"aud": "test-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	provider, err := oidc.NewProvider(context.Background(), providerURL)
	require.NoError(t, err)

	h := newTestOIDCHandler()
	h.Provider = provider
	h.OAuthConfig = oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   providerURL + "/auth",
			TokenURL:  providerURL + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
	require.NoError(t, h.Validate())

	var buf bytes.Buffer
	h.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate&code=authcode", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	req.AddCookie(&http.Cookie{Name: oidcNonceCookieName, Value: "somenonce"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid id_token")
	require.Contains(t, buf.String(), "OIDC id_token verification failed")
}

// ---------------------------------------------------------------------------
// Callback — Exchange and Verify failures log via slog.ErrorContext
// ---------------------------------------------------------------------------

func TestOIDCCallback_exchangeFailure_logsError(t *testing.T) {
	// Fake token endpoint that always returns HTTP 400 (provider/network error).
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad_request", http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	h := newTestOIDCHandler()
	h.OAuthConfig = oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/authorize",
			TokenURL: tokenServer.URL + "/token",
		},
	}

	var buf bytes.Buffer
	h.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate&code=authcode", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	req.AddCookie(&http.Cookie{Name: oidcNonceCookieName, Value: "somenonce"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, buf.String(), "OIDC code exchange failed")
}

func TestOIDCCallback_verifyFailure_logsError(t *testing.T) {
	// Fake OIDC discovery + JWKS server.  The token endpoint returns a
	// syntactically valid JSON body but with an id_token that is not a real JWT,
	// so verifier.Verify() will fail.
	var providerURL string
	discoveryMux := http.NewServeMux()
	providerServer := httptest.NewServer(discoveryMux)
	defer providerServer.Close()
	providerURL = providerServer.URL

	discoveryMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q,
			"id_token_signing_alg_values_supported": ["RS256"]
		}`, providerURL, providerURL+"/auth", providerURL+"/token", providerURL+"/jwks")
	})
	discoveryMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"keys":[]}`)
	})
	discoveryMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// id_token is not a valid JWT — Verify must reject it.
		_, _ = fmt.Fprint(w, `{"access_token":"tok","token_type":"bearer","id_token":"not.a.jwt"}`)
	})

	provider, err := oidc.NewProvider(context.Background(), providerURL)
	require.NoError(t, err)

	h := newTestOIDCHandler()
	h.Provider = provider
	h.OAuthConfig = oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   providerURL + "/auth",
			TokenURL:  providerURL + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
	require.NoError(t, h.Validate())

	var buf bytes.Buffer
	h.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))

	req := httptest.NewRequest(http.MethodGet, "/callback?state=mystate&code=authcode", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "mystate"})
	req.AddCookie(&http.Cookie{Name: oidcVerifierCookieName, Value: "someverifier"})
	req.AddCookie(&http.Cookie{Name: oidcNonceCookieName, Value: "somenonce"})
	w := httptest.NewRecorder()
	h.Callback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, buf.String(), "OIDC id_token verification failed")
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_missingUsers_returnsError(t *testing.T) {
	h := newTestOIDCHandler()
	h.Users = nil

	require.Error(t, h.Validate())
}

func TestValidate_missingJWT_returnsError(t *testing.T) {
	h := newTestOIDCHandler()
	h.JWT = nil

	require.Error(t, h.Validate())
}

func TestValidate_missingProvider_returnsError(t *testing.T) {
	h := newTestOIDCHandler()
	// Provider is nil by default in newTestOIDCHandler.
	require.Error(t, h.Validate())
}

func TestValidate_sessionsWithoutRefreshCookieName_returnsError(t *testing.T) {
	h := newTestOIDCHandler()
	h.Provider = newMockOIDCProvider(t)
	h.Sessions = &mockSessionStore{}
	// h.RefreshCookieName is "" (zero value)

	require.Error(t, h.Validate())
}

func TestValidate_sessionsWithRefreshCookieName_ok(t *testing.T) {
	h := newTestOIDCHandler()
	h.Provider = newMockOIDCProvider(t)
	h.Sessions = &mockSessionStore{}
	h.RefreshCookieName = "refresh"

	require.NoError(t, h.Validate())
}

func TestValidate_noSessions_ok(t *testing.T) {
	h := newTestOIDCHandler()
	h.Provider = newMockOIDCProvider(t)
	// Sessions is nil — RefreshCookieName is not required.
	require.NoError(t, h.Validate())
}
