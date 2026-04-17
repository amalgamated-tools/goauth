package handler

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

const magicLinkExpiry = 15 * time.Minute

// MagicLinkSender is called to deliver the one-time login token to the user.
// The token should be embedded in a URL that the user clicks to authenticate.
// Implementations are responsible for composing and sending the email.
type MagicLinkSender func(ctx context.Context, email, token string) error

// MagicLinkHandler holds dependencies for magic link (passwordless) endpoints.
type MagicLinkHandler struct {
	Users         auth.UserStore
	MagicLinks    auth.MagicLinkStore
	JWT           *auth.JWTManager
	Sessions      auth.SessionStore // optional; nil disables session tracking and refresh tokens
	// RefreshTokenTTL is the lifetime of refresh tokens. Defaults to
	// DefaultRefreshTokenTTL when Sessions is non-nil.
	RefreshTokenTTL time.Duration
	// RefreshCookieName is the name of the HttpOnly cookie used to store the
	// refresh token. When empty the refresh token is only returned in the
	// response body.
	RefreshCookieName string
	Sender            MagicLinkSender
	CookieName        string
	SecureCookies     bool
}

type magicLinkRequestBody struct {
	Email string `json:"email"`
}

// RequestMagicLink handles POST requests to generate a one-time login link.
//
// It creates a token, stores its SHA-256 hash, and invokes the Sender. The
// response is always 200 regardless of whether the email is registered, so
// that callers cannot enumerate valid addresses.
func (h *MagicLinkHandler) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	var req magicLinkRequestBody
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "email is required")
		return
	}

	if err := h.MagicLinks.DeleteExpiredMagicLinks(r.Context()); err != nil {
		slog.ErrorContext(r.Context(), "failed to delete expired magic links", slog.Any("error", err))
	}

	token, err := auth.GenerateRandomBase64(32)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	tokenHash := auth.HashHighEntropyToken(token)
	expiresAt := time.Now().UTC().Add(magicLinkExpiry)

	if _, err := h.MagicLinks.CreateMagicLink(r.Context(), req.Email, tokenHash, expiresAt); err != nil {
		slog.ErrorContext(r.Context(), "failed to create magic link", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create magic link")
		return
	}

	if h.Sender == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "magic link sending is not configured")
		return
	}
	if err := h.Sender(r.Context(), req.Email, token); err != nil {
		slog.ErrorContext(r.Context(), "failed to send magic link email",
			slog.Any("error", err))
		// Do not surface delivery failures to avoid leaking information.
	}

	writeJSON(r.Context(), w, http.StatusOK,
		map[string]string{"message": "if that email is valid, a login link has been sent"})
}

// VerifyMagicLink handles GET requests with a token query parameter.
//
// It consumes the token (one-time use), resolves or auto-provisions the
// user account for the associated email, and issues a session JWT.
func (h *MagicLinkHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "token is required")
		return
	}

	tokenHash := auth.HashHighEntropyToken(token)
	link, err := h.MagicLinks.FindAndDeleteMagicLink(r.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}
	if time.Now().UTC().After(link.ExpiresAt) {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	user, err := h.findOrCreateUser(r.Context(), link.Email)
	if err != nil {
		slog.ErrorContext(r.Context(), "magic link user resolution failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to resolve user")
		return
	}

	jwtToken, refreshToken, ok := h.issueTokens(w, r, user.ID)
	if !ok {
		return
	}

	writeJSON(r.Context(), w, http.StatusOK, AuthResponse{Token: jwtToken, RefreshToken: refreshToken, User: ToUserDTO(user)})
}

// issueTokens creates a new access JWT (and optionally a session with a refresh
// token) for the given user. It writes the access cookie and optional refresh
// cookie, and returns the tokens to embed in the response body. On any error it
// writes an HTTP error and returns false.
func (h *MagicLinkHandler) issueTokens(w http.ResponseWriter, r *http.Request, userID string) (accessToken, refreshToken string, ok bool) {
	if h.Sessions != nil {
		rawRefresh, err := auth.GenerateRandomHex(32)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to generate refresh token", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create session")
			return "", "", false
		}
		refreshHash := auth.HashHighEntropyToken(rawRefresh)

		ttl := h.RefreshTokenTTL
		if ttl <= 0 {
			ttl = DefaultRefreshTokenTTL
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		sess, err := h.Sessions.CreateSession(r.Context(), userID, refreshHash,
			r.UserAgent(), ip, time.Now().Add(ttl))
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to create session", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create session")
			return "", "", false
		}

		accessToken, err = h.JWT.CreateTokenWithSession(r.Context(), userID, sess.ID)
		if err != nil {
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
			return "", "", false
		}

		if h.RefreshCookieName != "" {
			SetRefreshCookie(w, rawRefresh, h.RefreshCookieName, h.SecureCookies, int(ttl.Seconds()))
		}
		SetAuthCookie(w, accessToken, h.CookieName, h.SecureCookies)
		return accessToken, rawRefresh, true
	}

	var err error
	accessToken, err = h.JWT.CreateToken(r.Context(), userID)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
		return "", "", false
	}
	SetAuthCookie(w, accessToken, h.CookieName, h.SecureCookies)
	return accessToken, "", true
}

// findOrCreateUser returns the existing user for the given email, or creates a
// new passwordless account if no record exists yet.
func (h *MagicLinkHandler) findOrCreateUser(ctx context.Context, email string) (*auth.User, error) {
	user, err := h.Users.FindByEmail(ctx, email)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}

	// Auto-provision: use the email address as the initial display name.
	created, err := h.Users.CreateUser(ctx, email, email, "")
	if err != nil {
		if errors.Is(err, auth.ErrEmailExists) {
			// Race condition: another request created the user concurrently.
			return h.Users.FindByEmail(ctx, email)
		}
		return nil, err
	}
	return created, nil
}
