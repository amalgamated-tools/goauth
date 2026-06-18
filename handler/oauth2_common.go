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
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"golang.org/x/oauth2"
)

type oauthCallbackFlow struct {
	VerifierValue string
	LinkUserID    string
	Code          string
}

// oauthLogin is the shared Login implementation for OIDCHandler and
// OAuth2Handler. It generates a random state and PKCE verifier, then calls
// redirect to send the browser to the provider's authorization endpoint.
func oauthLogin(
	w http.ResponseWriter, r *http.Request,
	logger *slog.Logger,
	stateErrMsg string,
	redirect func(http.ResponseWriter, *http.Request, string, string),
) {
	state, err := generateState()
	if err != nil {
		logger.ErrorContext(r.Context(), stateErrMsg, slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate login")
		return
	}
	verifier := oauth2.GenerateVerifier()
	redirect(w, r, state, verifier)
}

func redirectToOAuthProvider(
	w http.ResponseWriter, r *http.Request,
	stateCookieName, verifierCookieName string,
	ttl time.Duration,
	secureCookies bool,
	config *oauth2.Config,
	state, verifier string,
) {
	for _, pair := range [][2]string{
		{stateCookieName, state},
		{verifierCookieName, verifier},
	} {
		http.SetCookie(w, &http.Cookie{
			Name: pair[0], Value: pair[1], Path: "/",
			MaxAge: int(ttl.Seconds()), HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Secure: secureCookies,
		})
	}
	http.Redirect(w, r, config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func validateOAuthCallbackFlow(
	w http.ResponseWriter, r *http.Request,
	jwtMgr *auth.JWTManager,
	stateCookieName, verifierCookieName string,
	secureCookies bool,
) (*oauthCallbackFlow, bool) {
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing state cookie")
		return nil, false
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid state parameter")
		return nil, false
	}
	verifierCookie, err := r.Cookie(verifierCookieName)
	if err != nil || verifierCookie.Value == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing PKCE verifier cookie")
		return nil, false
	}

	for _, name := range []string{stateCookieName, verifierCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secureCookies,
		})
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		writeError(r.Context(), w, http.StatusUnauthorized, "authentication failed")
		return nil, false
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing authorization code")
		return nil, false
	}

	return &oauthCallbackFlow{
		VerifierValue: verifierCookie.Value,
		LinkUserID:    parseLinkState(jwtMgr, stateCookie.Value),
		Code:          code,
	}, true
}

// linkSubjectBestEffort attempts to link an OIDC subject to an existing user.
// A failure (other than ErrOIDCSubjectAlreadyLinked) is logged as a warning
// but does not prevent the caller from completing login.
func linkSubjectBestEffort(ctx context.Context, logger *slog.Logger, users auth.UserStore, userID, subject, path string) {
	err := users.LinkOIDCSubject(ctx, userID, subject)
	if err != nil && !errors.Is(err, auth.ErrOIDCSubjectAlreadyLinked) {
		logOrDefault(logger).WarnContext(ctx, "failed to link OIDC subject to email-matched user",
			slog.String("user_id", userID),
			slog.String("path", path),
			slog.Any("error", err),
		)
	}
}

// findOrCreateUser looks up the user identified by subject, falling back to
// email lookup and account creation. It handles concurrent-creation races by
// retrying the lookup when CreateOIDCUser returns ErrEmailExists.
func findOrCreateUser(ctx context.Context, logger *slog.Logger, users auth.UserStore, subject, email, name string) (*auth.User, error) {
	if user, err := users.FindByOIDCSubject(ctx, subject); err == nil {
		return user, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}
	if user, err := users.FindByEmail(ctx, email); err == nil {
		linkSubjectBestEffort(ctx, logger, users, user.ID, subject, "email_match")
		return user, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}
	if user, err := users.CreateOIDCUser(ctx, name, email, subject); err == nil {
		return user, nil
	} else if !errors.Is(err, auth.ErrEmailExists) {
		return nil, fmt.Errorf("create OIDC user: %w", err)
	}
	// Race retry: ErrEmailExists means another request already created the user
	// concurrently, so look them up instead.
	if u, err := users.FindByOIDCSubject(ctx, subject); err == nil {
		return u, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, fmt.Errorf("look up OIDC user after email race: %w", err)
	}
	u, err := users.FindByEmail(ctx, email)
	if err == nil {
		linkSubjectBestEffort(ctx, logger, users, u.ID, subject, "race_retry")
		return u, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, fmt.Errorf("look up user by email after email race: %w", err)
	}
	return nil, fmt.Errorf("failed to resolve user after race retry: %w", err)
}

// createLinkNonce issues a single-use account-linking nonce.
func createLinkNonce(w http.ResponseWriter, r *http.Request, logger *slog.Logger, store auth.OIDCLinkNonceStore, ttl time.Duration) {
	if store == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "account linking not configured")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	nonce, err := auth.GenerateRandomBase64(32)
	if err != nil {
		logOrDefault(logger).ErrorContext(r.Context(), "failed to generate link nonce", slog.Any("error", err), slog.String("user_id", userID))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate nonce")
		return
	}

	nonceHash := auth.HashHighEntropyToken(nonce)
	if _, err := store.CreateLinkNonce(r.Context(), userID, nonceHash, time.Now().UTC().Add(ttl)); err != nil {
		logOrDefault(logger).ErrorContext(r.Context(), "failed to store link nonce", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to store nonce")
		return
	}

	writeJSON(r.Context(), w, http.StatusOK, nonceBody{Nonce: nonce})
}

// handleLinkInitiation is the shared OAuth2/OIDC account-linking initiation
// handler. It validates the nonce and redirects to the provider with a signed
// state and PKCE verifier.
func handleLinkInitiation(
	w http.ResponseWriter, r *http.Request,
	nonces auth.OIDCLinkNonceStore,
	users auth.UserStore,
	jwtMgr *auth.JWTManager,
	logger *slog.Logger,
	provider string,
	generateState func() (string, error),
	redirect func(w http.ResponseWriter, r *http.Request, state, verifier string),
) {
	logger = logOrDefault(logger)
	if nonces == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "account linking not configured")
		return
	}
	nonceStr := r.URL.Query().Get("nonce")
	if nonceStr == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "missing nonce")
		return
	}
	userID, err := consumeLinkNonce(r.Context(), nonces, nonceStr)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusUnauthorized, "invalid or expired nonce")
		} else {
			logger.ErrorContext(r.Context(), "failed to consume link nonce", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to validate nonce")
		}
		return
	}
	u, err := users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "user not found")
		} else {
			logger.ErrorContext(r.Context(), "failed to look up user during link", slog.String("provider", provider), slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "server error")
		}
		return
	}
	if u.OIDCSubject != nil {
		writeError(r.Context(), w, http.StatusConflict, "cannot link account")
		return
	}

	state, err := generateState()
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to generate link state", slog.String("provider", provider), slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to initiate link")
		return
	}
	verifier := oauth2.GenerateVerifier()
	signedState := signLinkState(jwtMgr, state, userID)
	redirect(w, r, signedState, verifier)
}

// signLinkState encodes userID and produces an HMAC-signed state value that
// can be embedded in a redirect URL and later verified by parseLinkState.
func signLinkState(jwtMgr *auth.JWTManager, randomState, userID string) string {
	payload := randomState + "|" + userID
	sig := jwtMgr.HMACSign([]byte(payload))
	return randomState + "." + base64.RawURLEncoding.EncodeToString([]byte(userID)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// parseLinkState verifies the HMAC signature of a signed state value produced
// by signLinkState and returns the embedded userID. Returns "" on any error.
func parseLinkState(jwtMgr *auth.JWTManager, state string) string {
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
	if !jwtMgr.HMACVerify([]byte(parts[0]+"|"+userID), sig) {
		return ""
	}
	return userID
}

// generateState generates a cryptographically random base64 state value for
// OAuth2 and OIDC authorization flows.
func generateState() (string, error) {
	return auth.GenerateRandomBase64(32)
}

// consumeLinkNonce validates and atomically deletes the single-use link nonce,
// returning the associated userID. Returns auth.ErrNotFound when the nonce is
// missing or expired.
func consumeLinkNonce(ctx context.Context, store auth.OIDCLinkNonceStore, nonce string) (string, error) {
	nonceHash := auth.HashHighEntropyToken(nonce)
	entry, err := store.ConsumeAndDeleteLinkNonce(ctx, nonceHash)
	if err != nil {
		return "", err
	}
	if isExpired(entry.ExpiresAt) {
		return "", auth.ErrNotFound
	}
	return entry.UserID, nil
}

// handleLinkCallback is the shared OAuth2/OIDC account-linking callback
// handler. It validates that the link is safe to perform (no duplicate
// subjects), then calls LinkOIDCSubject. On success it redirects to
// successURL; on failure it redirects to "/?<errorParam>=<message>".
func handleLinkCallback(
	w http.ResponseWriter, r *http.Request,
	logger *slog.Logger,
	users auth.UserStore,
	linkUserID, subject string,
	successURL, errorParam string,
) {
	errRedirect := func(logMsg, redirectMsg string, logErr error) {
		if logMsg != "" && logErr != nil {
			logOrDefault(logger).ErrorContext(r.Context(), logMsg, slog.Any("error", logErr))
		}
		http.Redirect(w, r, "/?"+errorParam+"="+url.QueryEscape(redirectMsg), http.StatusFound)
	}

	user, err := users.FindByID(r.Context(), linkUserID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			errRedirect("", "User not found", nil)
		} else {
			errRedirect("failed to look up user during link", "Link verification failed", err)
		}
		return
	}
	if user.OIDCSubject != nil {
		errRedirect("", "Already linked", nil)
		return
	}
	if existing, err := users.FindByOIDCSubject(r.Context(), subject); err == nil {
		if existing.ID != linkUserID {
			errRedirect("", "SSO identity linked to another account", nil)
			return
		}
	} else if !errors.Is(err, auth.ErrNotFound) {
		errRedirect("failed to look up OIDC subject during link", "Link verification failed", err)
		return
	}
	if err := users.LinkOIDCSubject(r.Context(), linkUserID, subject); err != nil {
		errRedirect("failed to link OIDC subject", "Failed to link", err)
		return
	}
	http.Redirect(w, r, successURL, http.StatusFound)
}
