package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

type linkNonce struct {
	UserID    string
	ExpiresAt time.Time
}

// nonceBody is used instead of map[string]string to avoid a map allocation
// on the OIDC nonce response path.
type nonceBody struct {
	Nonce string `json:"nonce"`
}

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
	linkNonces        map[string]linkNonce
	linkNoncesMu      sync.Mutex
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
		linkNonces: make(map[string]linkNonce),
	}, nil
}

// Validate checks that the handler is correctly configured and returns an error
// if any required fields are missing or incompatible. Call Validate once at
// server startup, after setting all optional fields (Sessions, RefreshCookieName,
// etc.), so that misconfiguration is caught immediately rather than at the
// moment the first real user attempts to log in.
func (h *OIDCHandler) Validate() error {
	if h.Sessions != nil && h.RefreshCookieName == "" {
		return errors.New("OIDCHandler misconfigured: Sessions requires RefreshCookieName")
	}
	return nil
}

// issueTokens delegates to the package-level issueTokens helper.
func (h *OIDCHandler) issueTokens(w http.ResponseWriter, r *http.Request, userID string) (accessToken, refreshToken string, ok bool) {
	return issueTokens(w, r, userID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL)
}

func generateOIDCState() (string, error) {
	return auth.GenerateRandomBase64(32)
}

// Login redirects to the OIDC provider.
func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateOIDCState()
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate login")
		return
	}
	verifier := oauth2.GenerateVerifier()

	for _, c := range []http.Cookie{
		{Name: oidcStateCookieName, Value: state},
		{Name: oidcVerifierCookieName, Value: verifier},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: c.Name, Value: c.Value, Path: "/",
			MaxAge: int(oidcStateCookieTTL.Seconds()), HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}
	http.Redirect(w, r, h.OAuthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// Callback handles the OIDC provider redirect.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(oidcStateCookieName)
	if err != nil || cookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing state cookie")
		return
	}
	if r.URL.Query().Get("state") != cookie.Value {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid state parameter")
		return
	}
	verifierCookie, err := r.Cookie(oidcVerifierCookieName)
	if err != nil || verifierCookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing PKCE verifier cookie")
		return
	}

	// Clear flow cookies.
	for _, name := range []string{oidcStateCookieName, oidcVerifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}

	linkUserID := h.parseLinkState(cookie.Value)

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		writeError(r.Context(), w, http.StatusUnauthorized, "authentication failed")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing authorization code")
		return
	}

	oauth2Token, err := h.OAuthConfig.Exchange(r.Context(), code, oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to exchange code")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeError(r.Context(), w, http.StatusUnauthorized, "missing id_token")
		return
	}

	verifier := h.Provider.Verifier(&oidc.Config{ClientID: h.OAuthConfig.ClientID})
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
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

	if linkUserID == "" && (claims.EmailVerified == nil || !*claims.EmailVerified) {
		writeError(r.Context(), w, http.StatusUnauthorized, "OIDC email must be verified")
		return
	}

	if linkUserID != "" {
		h.handleLinkCallback(w, r, linkUserID, claims.Sub)
		return
	}

	user, err := h.findOrCreateUser(r.Context(), claims.Sub, claims.Email, claims.Name)
	if err != nil {
		slog.ErrorContext(r.Context(), "OIDC user resolution failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to process user")
		return
	}

	if _, _, issueOK := h.issueTokens(w, r, user.ID); !issueOK {
		return
	}

	http.Redirect(w, r, "/?oidc_login=1", http.StatusFound)
}

func (h *OIDCHandler) handleLinkCallback(w http.ResponseWriter, r *http.Request, linkUserID, subject string) {
	user, err := h.Users.FindByID(r.Context(), linkUserID)
	if err != nil {
		http.Redirect(w, r, "/?oidc_link_error="+url.QueryEscape("User not found"), http.StatusFound)
		return
	}
	if user.OIDCSubject != nil {
		http.Redirect(w, r, "/?oidc_link_error="+url.QueryEscape("Already linked"), http.StatusFound)
		return
	}
	if existing, err := h.Users.FindByOIDCSubject(r.Context(), subject); err == nil {
		if existing.ID != linkUserID {
			http.Redirect(w, r, "/?oidc_link_error="+url.QueryEscape("SSO identity linked to another account"), http.StatusFound)
			return
		}
	} else if !errors.Is(err, auth.ErrNotFound) {
		slog.ErrorContext(r.Context(), "failed to look up OIDC subject during link", slog.Any("error", err))
		http.Redirect(w, r, "/?oidc_link_error="+url.QueryEscape("Link verification failed"), http.StatusFound)
		return
	}
	if err := h.Users.LinkOIDCSubject(r.Context(), linkUserID, subject); err != nil {
		http.Redirect(w, r, "/?oidc_link_error="+url.QueryEscape("Failed to link"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/?oidc_linked=true", http.StatusFound)
}

func (h *OIDCHandler) linkOIDCSubjectBestEffort(ctx context.Context, userID, subject, path string) {
	err := h.Users.LinkOIDCSubject(ctx, userID, subject)
	if err != nil && !errors.Is(err, auth.ErrOIDCSubjectAlreadyLinked) {
		slog.WarnContext(ctx, "failed to link OIDC subject to email-matched user",
			slog.String("user_id", userID),
			slog.String("path", path),
			slog.Any("error", err),
		)
	}
}

func (h *OIDCHandler) findOrCreateUser(ctx context.Context, subject, email, name string) (*auth.User, error) {
	if user, err := h.Users.FindByOIDCSubject(ctx, subject); err == nil {
		return user, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}
	if user, err := h.Users.FindByEmail(ctx, email); err == nil {
		h.linkOIDCSubjectBestEffort(ctx, user.ID, subject, "email_match")
		return user, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}
	if user, err := h.Users.CreateOIDCUser(ctx, name, email, subject); err == nil {
		return user, nil
	} else if !errors.Is(err, auth.ErrEmailExists) {
		return nil, fmt.Errorf("create OIDC user: %w", err)
	}
	// Race retry: ErrEmailExists means another request already created the user
	// concurrently, so look them up instead.
	if u, err := h.Users.FindByOIDCSubject(ctx, subject); err == nil {
		return u, nil
	}
	if u, err := h.Users.FindByEmail(ctx, email); err == nil {
		h.linkOIDCSubjectBestEffort(ctx, u.ID, subject, "race_retry")
		return u, nil
	}
	return nil, fmt.Errorf("failed to resolve OIDC user")
}

// CreateLinkNonce issues a nonce for OIDC account linking.
func (h *OIDCHandler) CreateLinkNonce(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	nonce, err := generateOIDCState()
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate nonce")
		return
	}

	h.linkNoncesMu.Lock()
	now := time.Now()
	for k, v := range h.linkNonces {
		if now.After(v.ExpiresAt) {
			delete(h.linkNonces, k)
		}
	}
	h.linkNonces[nonce] = linkNonce{UserID: userID, ExpiresAt: now.Add(oidcStateCookieTTL)}
	h.linkNoncesMu.Unlock()

	writeJSON(r.Context(), w, http.StatusOK, nonceBody{Nonce: nonce})
}

// Link validates the nonce and redirects for account linking.
func (h *OIDCHandler) Link(w http.ResponseWriter, r *http.Request) {
	nonceStr := r.URL.Query().Get("nonce")
	if nonceStr == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing nonce")
		return
	}
	userID := h.consumeLinkNonce(nonceStr)
	if userID == "" {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired nonce")
		return
	}
	if u, err := h.Users.FindByID(r.Context(), userID); err != nil || u.OIDCSubject != nil {
		writeError(r.Context(), w, http.StatusConflict, "cannot link account")
		return
	}

	state, err := generateOIDCState()
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate link")
		return
	}
	verifier := oauth2.GenerateVerifier()
	signedState := h.signLinkState(state, userID)

	for _, c := range []http.Cookie{
		{Name: oidcStateCookieName, Value: signedState},
		{Name: oidcVerifierCookieName, Value: verifier},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: c.Name, Value: c.Value, Path: "/",
			MaxAge: int(oidcStateCookieTTL.Seconds()), HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}
	http.Redirect(w, r, h.OAuthConfig.AuthCodeURL(signedState, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (h *OIDCHandler) consumeLinkNonce(nonce string) string {
	h.linkNoncesMu.Lock()
	defer h.linkNoncesMu.Unlock()
	entry, ok := h.linkNonces[nonce]
	if !ok {
		return ""
	}
	delete(h.linkNonces, nonce)
	if time.Now().After(entry.ExpiresAt) {
		return ""
	}
	return entry.UserID
}

func (h *OIDCHandler) signLinkState(randomState, userID string) string {
	payload := randomState + "|" + userID
	sig := h.JWT.HMACSign([]byte(payload))
	return randomState + "." + base64.RawURLEncoding.EncodeToString([]byte(userID)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (h *OIDCHandler) parseLinkState(state string) string {
	parts := strings.SplitN(state, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	uidBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ""
	}
	userID := string(uidBytes)
	if !h.JWT.HMACVerify([]byte(parts[0]+"|"+userID), sig) {
		return ""
	}
	return userID
}
