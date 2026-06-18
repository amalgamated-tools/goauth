package handler

import (
	"context"
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
	// Name is the user's display name.
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
	// Logger is the structured logger used by the handler. When nil, the
	// process-wide slog.Default() logger is used.
	Logger *slog.Logger
}

// Validate checks that the handler is correctly configured and returns an error
// if any required fields are missing or incompatible. Call Validate once at
// server startup, after setting all optional fields, so that misconfiguration
// is caught immediately rather than at the first user login attempt.
func (h *OAuth2Handler) Validate() error {
	if err := requireField("OAuth2Handler", "Provider", h.Provider); err != nil {
		return err
	}
	if err := requireField("OAuth2Handler", "Users", h.Users); err != nil {
		return err
	}
	if err := requireField("OAuth2Handler", "JWT", h.JWT); err != nil {
		return err
	}
	return validateSessionConfig("OAuth2Handler", h.Sessions, h.RefreshCookieName)
}

func (h *OAuth2Handler) loginRedirectURL() string {
	if h.LoginRedirect == "" {
		return "/?oauth2_login=1"
	}
	return "/?" + h.LoginRedirect
}

// redirectToProvider sets the OAuth2 flow cookies and redirects the browser to
// the provider's authorization endpoint. state must already be signed when
// used for account linking.
func (h *OAuth2Handler) redirectToProvider(w http.ResponseWriter, r *http.Request, state, verifier string) {
	redirectToOAuthProvider(
		w, r,
		oauth2StateCookieName, oauth2VerifierCookieName,
		oauth2StateCookieTTL,
		h.SecureCookies,
		&h.OAuthConfig,
		state, verifier,
	)
}

// Login redirects the browser to the OAuth2 provider's authorisation endpoint.
// It sets short-lived HttpOnly state and PKCE verifier cookies (SameSite=Lax,
// 5-minute TTL) for CSRF and PKCE protection.
func (h *OAuth2Handler) Login(w http.ResponseWriter, r *http.Request) {
	oauthLogin(w, r, logOrDefault(h.Logger), "failed to generate OAuth2 login state", h.redirectToProvider)
}

// Callback handles the OAuth2 provider redirect. It validates the CSRF state
// and PKCE verifier, exchanges the authorisation code, fetches the user's
// identity via Provider.FetchUserInfo, and issues JWT/session cookies.
//
// On success it redirects to "/?<LoginRedirect>". All error responses are JSON.
func (h *OAuth2Handler) Callback(w http.ResponseWriter, r *http.Request) {
	flow, ok := validateOAuthCallbackFlow(w, r, h.JWT, oauth2StateCookieName, oauth2VerifierCookieName, h.SecureCookies)
	if !ok {
		return
	}

	token, err := h.OAuthConfig.Exchange(r.Context(), flow.Code, oauth2.VerifierOption(flow.VerifierValue))
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "OAuth2 code exchange failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to exchange code")
		return
	}

	info, err := h.Provider.FetchUserInfo(r.Context(), token)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "OAuth2 FetchUserInfo failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusUnauthorized, "failed to fetch user info")
		return
	}
	if info.Subject == "" || info.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "subject and email required")
		return
	}
	// For normal login flows the email must be verified; linking flows skip
	// this check because the user is already authenticated.
	if flow.LinkUserID == "" && !info.EmailVerified {
		writeError(r.Context(), w, http.StatusUnauthorized, "OAuth2 email must be verified")
		return
	}

	if flow.LinkUserID != "" {
		handleLinkCallback(w, r, h.Logger, h.Users, flow.LinkUserID, info.Subject, "/?oauth2_linked=true", "oauth2_link_error")
		return
	}

	user, err := findOrCreateUser(r.Context(), h.Logger, h.Users, info.Subject, info.Email, info.Name)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "OAuth2 user resolution failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to process user")
		return
	}

	if _, _, issueOK := issueTokens(w, r, h.Logger, user.ID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL); !issueOK {
		return
	}

	http.Redirect(w, r, h.loginRedirectURL(), http.StatusFound)
}

// CreateLinkNonce issues a single-use nonce for OAuth2 account linking.
// Requires auth middleware to be applied to the route.
func (h *OAuth2Handler) CreateLinkNonce(w http.ResponseWriter, r *http.Request) {
	createLinkNonce(w, r, h.Logger, h.LinkNonces, oauth2StateCookieTTL)
}

// Link validates the nonce and redirects the browser to the OAuth2 provider to
// start the account-linking flow. Requires auth middleware on the route.
func (h *OAuth2Handler) Link(w http.ResponseWriter, r *http.Request) {
	handleLinkInitiation(
		w, r,
		h.LinkNonces,
		h.Users,
		h.JWT,
		logOrDefault(h.Logger),
		"oauth2",
		generateState, h.redirectToProvider,
	)
}
