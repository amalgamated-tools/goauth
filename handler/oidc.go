package handler

import (
	"context"
	"errors"
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
	oidcStateCookieTTL     = 5 * time.Minute
)

// OIDCHandler holds dependencies for OIDC auth endpoints.
type OIDCHandler struct {
	Users         auth.UserStore
	JWT           *auth.JWTManager
	Provider      *oidc.Provider
	OAuthConfig   oauth2.Config
	CookieName    string
	SecureCookies bool
	Sessions      auth.SessionStore // optional; nil disables session tracking and refresh tokens
	// RefreshTokenTTL is the lifetime of refresh tokens. Defaults to
	// DefaultRefreshTokenTTL when Sessions is non-nil.
	RefreshTokenTTL time.Duration
	// RefreshCookieName is the name of the HttpOnly cookie used to store the
	// refresh token. Must be non-empty when Sessions is set; call Validate at
	// startup to catch this misconfiguration early.
	RefreshCookieName string
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

// log returns the handler's logger, falling back to slog.Default() when Logger
// is nil.
func (h *OIDCHandler) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
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
		CookieName: cookieName, SecureCookies: secureCookies,
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
	if h.Users == nil {
		return errors.New("OIDCHandler misconfigured: Users is required")
	}
	if h.JWT == nil {
		return errors.New("OIDCHandler misconfigured: JWT is required")
	}
	if h.Provider == nil {
		return errors.New("OIDCHandler misconfigured: Provider is required")
	}
	if err := validateSessionConfig("OIDCHandler", h.Sessions, h.RefreshCookieName); err != nil {
		return err
	}
	if h.IDTokenVerifier == nil {
		h.IDTokenVerifier = h.Provider.Verifier(&oidc.Config{ClientID: h.OAuthConfig.ClientID})
	}
	return nil
}

func generateOIDCState() (string, error) {
	return auth.GenerateRandomBase64(32)
}

// redirectToProvider sets the OIDC flow cookies and redirects the browser to
// the provider's authorization endpoint. state must already be signed when
// used for account linking.
func (h *OIDCHandler) redirectToProvider(w http.ResponseWriter, r *http.Request, state, verifier string) {
	redirectToOAuthProvider(
		w, r,
		oidcStateCookieName, oidcVerifierCookieName,
		oidcStateCookieTTL,
		h.SecureCookies,
		&h.OAuthConfig,
		state, verifier,
	)
}

// Login redirects to the OIDC provider.
func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateOIDCState()
	if err != nil {
		h.log().ErrorContext(r.Context(), "failed to generate OIDC login state", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate login")
		return
	}
	verifier := oauth2.GenerateVerifier()

	h.redirectToProvider(w, r, state, verifier)
}

// Callback handles the OIDC provider redirect.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	flow, ok := validateOAuthCallbackFlow(w, r, h.JWT, oidcStateCookieName, oidcVerifierCookieName, h.SecureCookies)
	if !ok {
		return
	}

	oauth2Token, err := h.OAuthConfig.Exchange(r.Context(), flow.Code, oauth2.VerifierOption(flow.VerifierValue))
	if err != nil {
		h.log().ErrorContext(r.Context(), "OIDC code exchange failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to exchange code")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeError(r.Context(), w, http.StatusUnauthorized, "missing id_token")
		return
	}

	verifier := h.IDTokenVerifier
	if verifier == nil {
		verifier = h.Provider.Verifier(&oidc.Config{ClientID: h.OAuthConfig.ClientID})
	}
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		h.log().ErrorContext(r.Context(), "OIDC id_token verification failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid id_token")
		return
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		h.log().ErrorContext(r.Context(), "failed to parse OIDC claims", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to parse claims")
		return
	}
	if claims.Sub == "" || claims.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "sub and email claims required")
		return
	}
	if claims.Name == "" {
		claims.Name = claims.Email
	}

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
		h.log().ErrorContext(r.Context(), "OIDC user resolution failed", slog.Any("error", err))
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
		h.log(),
		"oidc",
		generateOIDCState,
		h.redirectToProvider,
	)
}
