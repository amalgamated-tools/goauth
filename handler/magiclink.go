package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

const defaultMagicLinkTokenTTL = 15 * time.Minute

// MagicLinkSender is called to deliver the one-time login token to the user.
// The token should be embedded in a URL that the user clicks to authenticate.
// Implementations are responsible for composing and sending the email.
type MagicLinkSender func(ctx context.Context, email, token string) error

// MagicLinkHandler holds dependencies for magic link (passwordless) endpoints.
type MagicLinkHandler struct {
	Users         auth.UserStore
	MagicLinks    auth.MagicLinkStore
	JWT           tokenCreator
	Sender        MagicLinkSender
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
	// TokenTTL is how long a magic link token is valid. Defaults to
	// defaultMagicLinkTokenTTL (15 minutes) when unset or zero.
	TokenTTL time.Duration
	// Logger is the structured logger used by the handler. When nil, the
	// process-wide slog.Default() logger is used.
	Logger *slog.Logger
}

func (h *MagicLinkHandler) tokenTTL() time.Duration {
	return defaultDuration(h.TokenTTL, defaultMagicLinkTokenTTL)
}

type magicLinkRequestBody struct {
	Email string `json:"email"`
}

// Validate checks that the handler is correctly configured and returns an error
// if any required fields are missing or incompatible. Call Validate once at
// server startup, after setting all optional fields, so that misconfiguration
// is caught immediately rather than at the first real login attempt.
func (h *MagicLinkHandler) Validate() error {
	if err := requireField("MagicLinkHandler", "Users", h.Users); err != nil {
		return err
	}
	if err := requireField("MagicLinkHandler", "MagicLinks", h.MagicLinks); err != nil {
		return err
	}
	if err := requireField("MagicLinkHandler", "JWT", h.JWT); err != nil {
		return err
	}
	if err := requireField("MagicLinkHandler", "Sender", h.Sender); err != nil {
		return err
	}
	return validateSessionConfig("MagicLinkHandler", h.Sessions, h.RefreshCookieName)
}

// RequestMagicLink handles POST requests to generate a one-time login link.
//
// It creates a token, stores its SHA-256 hash, and invokes the Sender. The
// response is always 200 regardless of whether the email is registered, so
// that callers cannot enumerate valid addresses. Returns 503 if Sender is nil
// (misconfiguration).
func (h *MagicLinkHandler) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	if h.Sender == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "email sending not configured")
		return
	}
	var req magicLinkRequestBody
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "email is required")
		return
	}

	token, err := auth.GenerateRandomBase64(32)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to generate magic link token", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	tokenHash := auth.HashHighEntropyToken(token)
	expiresAt := time.Now().UTC().Add(h.tokenTTL())

	if _, err := h.MagicLinks.CreateMagicLink(r.Context(), req.Email, tokenHash, expiresAt); err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to create magic link", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create magic link")
		return
	}
	if err := h.Sender(r.Context(), req.Email, token); err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to send magic link email",
			slog.Any("error", err))
		// Delete the orphaned token so state stays consistent.
		if _, delErr := h.MagicLinks.FindAndDeleteMagicLink(r.Context(), tokenHash); delErr != nil && !errors.Is(delErr, auth.ErrNotFound) {
			logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to delete orphaned magic link", slog.Any("error", delErr))
		}
	}

	writeJSON(r.Context(), w, http.StatusOK,
		messageBody{Message: "if that email is valid, a login link has been sent"})
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
		logOrDefault(h.Logger).ErrorContext(r.Context(), "failed to find magic link", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}
	if time.Now().UTC().After(link.ExpiresAt) {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	user, err := h.findOrCreateUser(r.Context(), link.Email)
	if err != nil {
		logOrDefault(h.Logger).ErrorContext(r.Context(), "magic link user resolution failed", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to resolve user")
		return
	}

	jwtToken, refreshToken, ok := issueTokens(w, r, user.ID, h.Sessions, h.JWT, h.CookieName, h.SecureCookies, h.RefreshCookieName, h.RefreshTokenTTL)
	if !ok {
		return
	}

	setNoCacheHeaders(w)
	writeJSON(r.Context(), w, http.StatusOK, AuthResponse{Token: jwtToken, RefreshToken: refreshToken, User: ToUserDTO(user)})
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

	// Auto-provision: leave the display name blank so the consuming app can
	// prompt the user on first login.
	created, err := h.Users.CreateUser(ctx, "", email, "")
	if err != nil {
		if errors.Is(err, auth.ErrEmailExists) {
			// Race condition: another request created the user concurrently.
			return h.Users.FindByEmail(ctx, email)
		}
		return nil, err
	}
	return created, nil
}
