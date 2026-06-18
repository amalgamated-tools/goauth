package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookieName    = "oidc_state"
	oidcVerifierCookieName = "oidc_verifier"
	oidcNonceCookieName    = "oidc_nonce"
	oidcStateCookieTTL     = 5 * time.Minute
)

// OIDCHandler holds dependencies for OIDC auth endpoints.
type OIDCHandler struct {
	Users       auth.UserStore
	JWT         *auth.JWTManager
	Provider    *oidc.Provider
	OAuthConfig oauth2.Config
	SessionConfig
	// LinkNonces is the store used to persist single-use account-linking nonces.
	// When nil, CreateLinkNonce and Link return HTTP 503.
	LinkNonces auth.OIDCLinkNonceStore
	// IDTokenVerifier is cached at construction / Validate() time to avoid
	// recreating an identical verifier on every Callback invocation. Leave nil
	// to let NewOIDCHandler or Validate populate it automatically.
	IDTokenVerifier *oidc.IDTokenVerifier
	// Logger is the structured logger used by the handler. When nil, the
	// process-wide slog.Default() logger is used.
	Logger *slog.Logger
}

// NewOIDCHandler creates an OIDCHandler by performing OIDC discovery.
func NewOIDCHandler(ctx context.Context, users auth.UserStore, jwt *auth.JWTManager, issuerURL, clientID, clientSecret, redirectURI, cookieName string, secureCookies bool) (*OIDCHandler, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider discovery: %w", err)
	}
	return &OIDCHandler{
		Users: users, JWT: jwt, Provider: provider,
		OAuthConfig: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret,
			RedirectURL: redirectURI, Endpoint: provider.Endpoint(),
			Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
		SessionConfig:   SessionConfig{CookieName: cookieName, SecureCookies: secureCookies},
		IDTokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

// Validate checks that the handler is correctly configured and returns an error
// if any required fields are missing or incompatible. It also initializes
// IDTokenVerifier from Provider when the field is nil, so callers that do not
// use NewOIDCHandler still benefit from the cached verifier. Call Validate once
// at server startup, before the handler begins serving requests, after setting
// all optional fields (Sessions, RefreshCookieName, etc.).
func (h *OIDCHandler) Validate() error {
	if err := requireField("OIDCHandler", "Users", h.Users); err != nil {
		return err
	}
	if err := requireField("OIDCHandler", "JWT", h.JWT); err != nil {
		return err
	}
	if err := requireField("OIDCHandler", "Provider", h.Provider); err != nil {
		return err
	}
	if err := h.validate("OIDCHandler"); err != nil {
		return err
	}
	if h.IDTokenVerifier == nil {
		h.IDTokenVerifier = h.Provider.Verifier(&oidc.Config{ClientID: h.OAuthConfig.ClientID})
	}
	return nil
}

// redirectToProvider sets the OIDC flow cookies and redirects the browser to
// the provider's authorization endpoint. state must already be signed when
// used for account linking.
func (h *OIDCHandler) redirectToProvider(w http.ResponseWriter, r *http.Request, state, verifier string) {
	nonce, err := auth.GenerateRandomBase64(32)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to generate OIDC nonce", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate authentication")
		return
	}
	for _, pair := range [][2]string{
		{oidcStateCookieName, state},
		{oidcVerifierCookieName, verifier},
		{oidcNonceCookieName, nonce},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: pair[0], Value: pair[1], Path: "/",
			MaxAge: int(oidcStateCookieTTL.Seconds()), HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}
	http.Redirect(w, r, h.OAuthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), http.StatusFound)
}

// Login redirects to the OIDC provider.
func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	oauthLogin(w, r, logOrDefault(h.Logger), "failed to generate OIDC login state", h.redirectToProvider)
}

// Callback handles the OIDC provider redirect.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	flow, ok := validateOAuthCallbackFlow(w, r, h.JWT, oidcStateCookieName, oidcVerifierCookieName, h.SecureCookies)
	if !ok {
		return
	}
	nonceCookie, err := r.Cookie(oidcNonceCookieName)
	if err != nil || nonceCookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing OIDC nonce cookie")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcNonceCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
	})

	oauth2Token, err := h.OAuthConfig.Exchange(r.Context(), flow.Code, oauth2.VerifierOption(flow.VerifierValue))
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "OIDC code exchange failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to exchange code")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeError(r.Context(), w, http.StatusUnauthorized, "missing id_token")
		return
	}

	idToken, err := h.IDTokenVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "OIDC id_token verification failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid id_token")
		return
	}
	if idToken.Nonce != nonceCookie.Value {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid nonce")
		return
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to parse OIDC claims", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to parse claims")
		return
	}
	if claims.Sub == "" || claims.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "sub and email claims required")
		return
	}
	// Linking is initiated by an already-authenticated local user, so only
	// login/signup flows require a verified IdP email claim.
	if flow.LinkUserID == "" && (claims.EmailVerified == nil || !*claims.EmailVerified) {
		writeError(r.Context(), w, http.StatusUnauthorized, "OIDC email must be verified")
		return
	}

	if flow.LinkUserID != "" {
		handleLinkCallback(w, r, h.Users, flow.LinkUserID, claims.Sub, "/?oidc_linked=true", "oidc_link_error")
		return
	}

	user, err := findOrCreateUser(r.Context(), h.Users, claims.Sub, claims.Email, claims.Name)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "OIDC user resolution failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to process user")
		return
	}

	if _, _, issueOK := issueTokens(w, r, user.ID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL); !issueOK {
		return
	}

	http.Redirect(w, r, "/?oidc_login=1", http.StatusFound)
}

// CreateLinkNonce issues a nonce for OIDC account linking.
func (h *OIDCHandler) CreateLinkNonce(w http.ResponseWriter, r *http.Request) {
	createLinkNonce(w, r, h.LinkNonces, oidcStateCookieTTL)
}

// Link validates the nonce and redirects for account linking.
func (h *OIDCHandler) Link(w http.ResponseWriter, r *http.Request) {
	handleLinkInitiation(
		w, r,
		h.LinkNonces,
		h.Users,
		h.JWT,
		logOrDefault(h.Logger),
		"oidc",
		generateState,
		h.redirectToProvider,
	)
}
