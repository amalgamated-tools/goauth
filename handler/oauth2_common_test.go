package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRedirectToOAuthProvider_setsCookiesAndRedirects(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	cfg := oauth2.Config{
		ClientID: "client-id",
		Endpoint: oauth2.Endpoint{AuthURL: "https://example.com/authorize"},
	}

	redirectToOAuthProvider(w, req, "state_cookie", "verifier_cookie", 5*time.Minute, true, &cfg, "state-value", "verifier-value")

	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "https://example.com/authorize")

	var sawState, sawVerifier bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "state_cookie":
			sawState = true
			require.Equal(t, "state-value", c.Value)
			require.Equal(t, int((5 * time.Minute).Seconds()), c.MaxAge)
			require.True(t, c.Secure)
		case "verifier_cookie":
			sawVerifier = true
			require.Equal(t, "verifier-value", c.Value)
			require.Equal(t, int((5 * time.Minute).Seconds()), c.MaxAge)
			require.True(t, c.Secure)
		}
	}
	require.True(t, sawState)
	require.True(t, sawVerifier)
}

func TestValidateOAuthCallbackFlow_success(t *testing.T) {
	jwtMgr := newTestJWT()
	signedState := signLinkState(jwtMgr, "random-state", "user-123")

	req := httptest.NewRequest(http.MethodGet, "/callback?state="+signedState+"&code=auth-code", nil)
	req.AddCookie(&http.Cookie{Name: "state_cookie", Value: signedState})
	req.AddCookie(&http.Cookie{Name: "verifier_cookie", Value: "verifier-value"})
	w := httptest.NewRecorder()

	flow, ok := validateOAuthCallbackFlow(w, req, jwtMgr, "state_cookie", "verifier_cookie", true)

	require.True(t, ok)
	require.NotNil(t, flow)
	require.Equal(t, "verifier-value", flow.VerifierValue)
	require.Equal(t, "user-123", flow.LinkUserID)
	require.Equal(t, "auth-code", flow.Code)

	var clearedState, clearedVerifier bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "state_cookie":
			clearedState = true
			require.Equal(t, -1, c.MaxAge)
		case "verifier_cookie":
			clearedVerifier = true
			require.Equal(t, -1, c.MaxAge)
		}
	}
	require.True(t, clearedState)
	require.True(t, clearedVerifier)
}

func TestValidateOAuthCallbackFlow_missingStateCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	w := httptest.NewRecorder()

	flow, ok := validateOAuthCallbackFlow(w, req, newTestJWT(), "state_cookie", "verifier_cookie", false)

	require.False(t, ok)
	require.Nil(t, flow)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateOAuthCallbackFlow_stateMismatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?state=wrong&code=c", nil)
	req.AddCookie(&http.Cookie{Name: "state_cookie", Value: "correct-state"})
	w := httptest.NewRecorder()

	flow, ok := validateOAuthCallbackFlow(w, req, newTestJWT(), "state_cookie", "verifier_cookie", false)

	require.False(t, ok)
	require.Nil(t, flow)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateOAuthCallbackFlow_missingVerifierCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	req.AddCookie(&http.Cookie{Name: "state_cookie", Value: "s"})
	w := httptest.NewRecorder()

	flow, ok := validateOAuthCallbackFlow(w, req, newTestJWT(), "state_cookie", "verifier_cookie", false)

	require.False(t, ok)
	require.Nil(t, flow)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestValidateOAuthCallbackFlow_providerError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&error=access_denied", nil)
	req.AddCookie(&http.Cookie{Name: "state_cookie", Value: "s"})
	req.AddCookie(&http.Cookie{Name: "verifier_cookie", Value: "v"})
	w := httptest.NewRecorder()

	flow, ok := validateOAuthCallbackFlow(w, req, newTestJWT(), "state_cookie", "verifier_cookie", false)

	require.False(t, ok)
	require.Nil(t, flow)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestValidateOAuthCallbackFlow_missingCode(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?state=s", nil)
	req.AddCookie(&http.Cookie{Name: "state_cookie", Value: "s"})
	req.AddCookie(&http.Cookie{Name: "verifier_cookie", Value: "v"})
	w := httptest.NewRecorder()

	flow, ok := validateOAuthCallbackFlow(w, req, newTestJWT(), "state_cookie", "verifier_cookie", false)

	require.False(t, ok)
	require.Nil(t, flow)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLinkInitiation_missingNonce(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/link", nil)
	w := httptest.NewRecorder()

	handleLinkInitiation(
		w, req,
		&mockOIDCLinkNonceStore{},
		&mockUserStore{},
		newTestJWT(),
		nil,
		func() (string, error) { return "state", nil },
		func(http.ResponseWriter, *http.Request, string, string) {},
	)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLinkInitiation_successCallsRedirect(t *testing.T) {
	nonces := &mockOIDCLinkNonceStore{}
	const userID = "user-123"
	const nonce = "nonce-123"
	_, err := nonces.CreateLinkNonce(context.Background(), userID, auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()

	redirectCalled := false
	var gotSignedState, gotVerifier string
	handleLinkInitiation(
		w, req,
		nonces,
		&mockUserStore{
			findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
				require.Equal(t, userID, id)
				return &auth.User{ID: id}, nil
			},
		},
		newTestJWT(),
		nil,
		func() (string, error) { return "random-state", nil },
		func(_ http.ResponseWriter, _ *http.Request, state, verifier string) {
			redirectCalled = true
			gotSignedState = state
			gotVerifier = verifier
		},
	)

	require.True(t, redirectCalled)
	require.Equal(t, userID, parseLinkState(newTestJWT(), gotSignedState))
	require.NotEmpty(t, gotVerifier)
}

func TestHandleLinkInitiation_stateGenerationError(t *testing.T) {
	nonces := &mockOIDCLinkNonceStore{}
	const nonce = "nonce-err"
	_, err := nonces.CreateLinkNonce(context.Background(), "user-1", auth.HashHighEntropyToken(nonce), time.Now().Add(time.Minute))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/link?nonce="+nonce, nil)
	w := httptest.NewRecorder()

	handleLinkInitiation(
		w, req,
		nonces,
		&mockUserStore{
			findByIDFunc: func(_ context.Context, id string) (*auth.User, error) {
				return &auth.User{ID: id}, nil
			},
		},
		newTestJWT(),
		nil,
		func() (string, error) { return "", errors.New("entropy source failed") },
		func(http.ResponseWriter, *http.Request, string, string) {
			t.Fatal("redirect should not be called when state generation fails")
		},
	)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}
