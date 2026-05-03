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
)

// linkSubjectBestEffort attempts to link an OIDC subject to an existing user.
// A failure (other than ErrOIDCSubjectAlreadyLinked) is logged as a warning
// but does not prevent the caller from completing login.
func linkSubjectBestEffort(ctx context.Context, users auth.UserStore, userID, subject, path string) {
	err := users.LinkOIDCSubject(ctx, userID, subject)
	if err != nil && !errors.Is(err, auth.ErrOIDCSubjectAlreadyLinked) {
		slog.WarnContext(ctx, "failed to link OIDC subject to email-matched user",
			slog.String("user_id", userID),
			slog.String("path", path),
			slog.Any("error", err),
		)
	}
}

// findOrCreateUser looks up the user identified by subject, falling back to
// email lookup and account creation. It handles concurrent-creation races by
// retrying the lookup when CreateOIDCUser returns ErrEmailExists.
func findOrCreateUser(ctx context.Context, users auth.UserStore, subject, email, name string) (*auth.User, error) {
	if user, err := users.FindByOIDCSubject(ctx, subject); err == nil {
		return user, nil
	} else if !errors.Is(err, auth.ErrNotFound) {
		return nil, err
	}
	if user, err := users.FindByEmail(ctx, email); err == nil {
		linkSubjectBestEffort(ctx, users, user.ID, subject, "email_match")
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
	}
	if u, err := users.FindByEmail(ctx, email); err == nil {
		linkSubjectBestEffort(ctx, users, u.ID, subject, "race_retry")
		return u, nil
	}
	return nil, fmt.Errorf("failed to resolve OIDC user")
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

// consumeLinkNonce validates and atomically deletes the single-use link nonce,
// returning the associated userID. Returns auth.ErrNotFound when the nonce is
// missing or expired.
func consumeLinkNonce(ctx context.Context, store auth.OIDCLinkNonceStore, nonce string) (string, error) {
	nonceHash := auth.HashHighEntropyToken(nonce)
	entry, err := store.ConsumeAndDeleteLinkNonce(ctx, nonceHash)
	if err != nil {
		return "", err
	}
	if time.Now().UTC().After(entry.ExpiresAt) {
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
	users auth.UserStore,
	linkUserID, subject string,
	successURL, errorParam string,
) {
	errRedirect := func(logMsg, redirectMsg string, logErr ...any) {
		if logMsg != "" {
			args := append([]any{"error"}, logErr...)
			slog.ErrorContext(r.Context(), logMsg, args...)
		}
		http.Redirect(w, r, "/?"+errorParam+"="+url.QueryEscape(redirectMsg), http.StatusFound)
	}

	user, err := users.FindByID(r.Context(), linkUserID)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			errRedirect("", "User not found")
		} else {
			errRedirect("failed to look up user during link", "Link verification failed", err)
		}
		return
	}
	if user.OIDCSubject != nil {
		errRedirect("", "Already linked")
		return
	}
	if existing, err := users.FindByOIDCSubject(r.Context(), subject); err == nil {
		if existing.ID != linkUserID {
			errRedirect("", "SSO identity linked to another account")
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
