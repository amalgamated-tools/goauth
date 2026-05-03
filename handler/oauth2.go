package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"golang.org/x/oauth2"
)

// OAuth2UserInfo is the normalised identity returned by an OAuth2IdentityProvider.
type OAuth2UserInfo struct {
	// Subject is the provider's stable unique identifier for the user.
	// Use a provider-specific prefix (e.g. "github:<id>") to avoid collisions
	// with subjects from other providers or OIDC.
	Subject string
	// Email is the user's email address. Must be non-empty.
	Email string
	// Name is the user's display name. When empty, Email is used as a fallback.
	Name string
	// EmailVerified reports whether the provider has confirmed the email address.
	// OAuth2Handler rejects logins (but not link flows) when this is false.
	EmailVerified bool
}

// OAuth2IdentityProvider fetches a normalised user identity from a provider's
// API using a live access token. Implement this interface for each OAuth2
// provider you want to support.
type OAuth2IdentityProvider interface {
	// FetchUserInfo exchanges the access token for a normalised OAuth2UserInfo.
	// Returns a non-nil error if the provider API call fails.
	FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error)
}

const (
	oauth2StateCookieName    = "oauth2_state"
	oauth2VerifierCookieName = "oauth2_verifier"
	oauth2StateCookieTTL     = 5 * time.Minute
)

// OAuth2Handler holds dependencies for generic OAuth2 auth endpoints. It uses
// an OAuth2IdentityProvider to obtain user identity, so it works with any
// OAuth2-based provider (GitHub, Discord, Slack, etc.).
//
// For providers that support OpenID Connect (Google, Microsoft, Okta), prefer
// OIDCHandler, which performs standards-compliant id_token verification.
type OAuth2Handler struct {
	Users       auth.UserStore
	JWT         *auth.JWTManager
	OAuthConfig oauth2.Config
	// Provider fetches the user's identity from the OAuth2 provider after code
	// exchange. Must be non-nil.
	Provider      OAuth2IdentityProvider
	CookieName    string
	SecureCookies bool
	// Sessions is optional; nil disables session tracking and refresh tokens.
	Sessions auth.SessionStore
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
	// LoginRedirect is the query string appended to "/" after a successful login
	// callback (e.g. "github_login=1" → redirects to "/?github_login=1").
	// Defaults to "oauth2_login=1" when empty.
	LoginRedirect string
}

// Validate checks that the handler is correctly configured and returns an error
// if any required fields are missing or incompatible. Call Validate once at
// server startup, after setting all optional fields, so that misconfiguration
// is caught immediately rather than at the first user login attempt.
func (h *OAuth2Handler) Validate() error {
	if h.Sessions != nil && h.RefreshCookieName == "" {
		return errors.New("OAuth2Handler misconfigured: Sessions requires RefreshCookieName")
	}
	return nil
}

func (h *OAuth2Handler) issueTokens(w http.ResponseWriter, r *http.Request, userID string) (accessToken, refreshToken string, ok bool) {
	return issueTokens(w, r, userID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL)
}

func (h *OAuth2Handler) loginRedirectURL() string {
	if h.LoginRedirect == "" {
		return "/?oauth2_login=1"
	}
	return "/?" + h.LoginRedirect
}

// Login redirects the browser to the OAuth2 provider's authorisation endpoint.
// It sets short-lived HttpOnly state and PKCE verifier cookies (SameSite=Lax,
// 5-minute TTL) for CSRF and PKCE protection.
func (h *OAuth2Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := auth.GenerateRandomBase64(32)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate login")
		return
	}
	verifier := oauth2.GenerateVerifier()

	for _, c := range []http.Cookie{
		{Name: oauth2StateCookieName, Value: state},
		{Name: oauth2VerifierCookieName, Value: verifier},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: c.Name, Value: c.Value, Path: "/",
			MaxAge: int(oauth2StateCookieTTL.Seconds()), HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}
	http.Redirect(w, r, h.OAuthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// Callback handles the OAuth2 provider redirect. It validates the CSRF state
// and PKCE verifier, exchanges the authorisation code, fetches the user's
// identity via Provider.FetchUserInfo, and issues JWT/session cookies.
//
// On success it redirects to "/?<LoginRedirect>". All error responses are JSON.
func (h *OAuth2Handler) Callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(oauth2StateCookieName)
	if err != nil || stateCookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing state cookie")
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid state parameter")
		return
	}
	verifierCookie, err := r.Cookie(oauth2VerifierCookieName)
	if err != nil || verifierCookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing PKCE verifier cookie")
		return
	}

	// Clear flow cookies.
	for _, name := range []string{oauth2StateCookieName, oauth2VerifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}

	linkUserID := parseLinkState(h.JWT, stateCookie.Value)

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		writeError(r.Context(), w, http.StatusUnauthorized, "authentication failed")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing authorization code")
		return
	}

	token, err := h.OAuthConfig.Exchange(r.Context(), code, oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to exchange code")
		return
	}

	info, err := h.Provider.FetchUserInfo(r.Context(), token)
	if err != nil {
		slog.ErrorContext(r.Context(), "OAuth2 FetchUserInfo failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to fetch user info")
		return
	}
	if info.Subject == "" || info.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "subject and email required")
		return
	}
	if info.Name == "" {
		info.Name = info.Email
	}

	// For normal login flows the email must be verified; linking flows skip
	// this check because the user is already authenticated.
	if linkUserID == "" && !info.EmailVerified {
		writeError(r.Context(), w, http.StatusUnauthorized, "OAuth2 email must be verified")
		return
	}

	if linkUserID != "" {
		handleLinkCallback(w, r, h.Users, linkUserID, info.Subject, "/?oauth2_linked=true", "oauth2_link_error")
		return
	}

	user, err := findOrCreateUser(r.Context(), h.Users, info.Subject, info.Email, info.Name)
	if err != nil {
		slog.ErrorContext(r.Context(), "OAuth2 user resolution failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to process user")
		return
	}

	if _, _, issueOK := h.issueTokens(w, r, user.ID); !issueOK {
		return
	}

	http.Redirect(w, r, h.loginRedirectURL(), http.StatusFound)
}

// CreateLinkNonce issues a single-use nonce for OAuth2 account linking.
// Requires auth middleware to be applied to the route.
func (h *OAuth2Handler) CreateLinkNonce(w http.ResponseWriter, r *http.Request) {
	if h.LinkNonces == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "account linking not configured")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	nonce, err := auth.GenerateRandomBase64(32)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate nonce")
		return
	}

	nonceHash := auth.HashHighEntropyToken(nonce)
	if _, err := h.LinkNonces.CreateLinkNonce(r.Context(), userID, nonceHash, time.Now().UTC().Add(oauth2StateCookieTTL)); err != nil {
		slog.ErrorContext(r.Context(), "failed to store link nonce", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to store nonce")
		return
	}

	writeJSON(r.Context(), w, http.StatusOK, nonceBody{Nonce: nonce})
}

// Link validates the nonce and redirects the browser to the OAuth2 provider to
// start the account-linking flow. Requires auth middleware on the route.
func (h *OAuth2Handler) Link(w http.ResponseWriter, r *http.Request) {
	if h.LinkNonces == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "account linking not configured")
		return
	}
	nonceStr := r.URL.Query().Get("nonce")
	if nonceStr == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing nonce")
		return
	}
	userID, err := consumeLinkNonce(r.Context(), h.LinkNonces, nonceStr)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired nonce")
		} else {
			slog.ErrorContext(r.Context(), "failed to consume link nonce", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to validate nonce")
		}
		return
	}
	u, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusConflict, "cannot link account")
		} else {
			slog.ErrorContext(r.Context(), "failed to look up user during OAuth2 link", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "server error")
		}
		return
	}
	if u.OIDCSubject != nil {
		writeError(r.Context(), w, http.StatusConflict, "cannot link account")
		return
	}

	state, err := auth.GenerateRandomBase64(32)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate link")
		return
	}
	verifier := oauth2.GenerateVerifier()
	signedState := signLinkState(h.JWT, state, userID)

	for _, c := range []http.Cookie{
		{Name: oauth2StateCookieName, Value: signedState},
		{Name: oauth2VerifierCookieName, Value: verifier},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: c.Name, Value: c.Value, Path: "/",
			MaxAge: int(oauth2StateCookieTTL.Seconds()), HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: h.SecureCookies,
		})
	}
	http.Redirect(w, r, h.OAuthConfig.AuthCodeURL(signedState, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}
