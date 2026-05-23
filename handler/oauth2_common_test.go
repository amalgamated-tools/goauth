package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	require.Equal(t, signedState, flow.StateValue)
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
