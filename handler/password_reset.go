package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
	"golang.org/x/crypto/bcrypt"
)

const (
	passwordResetTokenBytes = 32
	defaultPasswordResetTTL = time.Hour
)

// PasswordResetHandler handles email-based password reset flows.
//
// If SendResetEmail is nil, RequestReset returns HTTP 503 before any database
// write, treating a missing sender as a misconfiguration error.
type PasswordResetHandler struct {
	Users  auth.UserStore
	Resets auth.PasswordResetStore
	// SendResetEmail is called with the recipient's email address and the raw
	// (unhashed) reset token. The consuming application is responsible for
	// composing and delivering the email containing the token.
	SendResetEmail func(ctx context.Context, toEmail, rawToken string) error
	// TokenTTL controls how long a reset token remains valid. Defaults to 1 hour.
	TokenTTL time.Duration
	// RateLimiter, if set, is applied to RequestReset to guard against abuse.
	RateLimiter *auth.RateLimiter
}

type requestResetRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (h *PasswordResetHandler) tokenTTL() time.Duration {
	if h.TokenTTL > 0 {
		return h.TokenTTL
	}
	return defaultPasswordResetTTL
}

// RequestReset handles POST /password-reset/request. It accepts an email
// address, generates a secure reset token, persists its hash, and delivers
// the raw token via SendResetEmail. Returns 503 if SendResetEmail is nil
// (misconfiguration); otherwise always returns 200 OK to avoid leaking
// whether the email address is registered.
func (h *PasswordResetHandler) RequestReset(w http.ResponseWriter, r *http.Request) {
	if h.RateLimiter != nil && !h.RateLimiter.Allow(r) {
		writeError(r.Context(), w, http.StatusTooManyRequests, "too many requests")
		return
	}

	var req requestResetRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "email is required")
		return
	}

	if h.SendResetEmail == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "password reset sending is not configured")
		return
	}

	user, err := h.Users.FindByEmail(r.Context(), req.Email)
	if err != nil && !errors.Is(err, auth.ErrNotFound) {
		slog.ErrorContext(r.Context(), "password reset: lookup user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Only create a token for password-auth-capable accounts. OIDC-only
	// accounts (PasswordHash == "") cannot use the password reset flow.
	if user != nil && user.PasswordHash != "" {
		rawToken, err := auth.GenerateRandomBase64(passwordResetTokenBytes)
		if err != nil {
			slog.ErrorContext(r.Context(), "password reset: generate token", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
			return
		}
		tokenHash := auth.HashHighEntropyToken(rawToken)
		expiresAt := time.Now().Add(h.tokenTTL())

		token, err := h.Resets.CreatePasswordResetToken(r.Context(), user.ID, tokenHash, expiresAt)
		if err != nil {
			slog.ErrorContext(r.Context(), "password reset: store token", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
			return
		}

		if err := h.SendResetEmail(r.Context(), user.Email, rawToken); err != nil {
			slog.ErrorContext(r.Context(), "password reset: send email", slog.Any("error", err))
			// Delete the orphaned token so state stays consistent.
			if delErr := h.Resets.DeletePasswordResetToken(r.Context(), token.ID); delErr != nil {
				slog.ErrorContext(r.Context(), "password reset: cleanup token after email failure", slog.Any("error", delErr))
			}
		}
	}

	// Always return 200 to avoid leaking whether the email is registered.
	writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: "if that email is registered, a reset link has been sent"})
}

// ResetPassword handles POST /password-reset/confirm. It validates the token,
// updates the user's password, and consumes (deletes) the token.
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	if req.Token == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "token is required")
		return
	}
	if !validatePassword(r.Context(), w, req.NewPassword) {
		return
	}

	tokenHash := auth.HashHighEntropyToken(req.Token)
	resetToken, err := h.Resets.FindPasswordResetToken(r.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrExpiredToken) {
			writeError(r.Context(), w, http.StatusBadRequest, "invalid or expired reset token")
			return
		}
		slog.ErrorContext(r.Context(), "password reset: find token", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}
	if time.Now().After(resetToken.ExpiresAt) {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid or expired reset token")
		return
	}

	// Guard against resetting passwords on OIDC-only accounts.
	user, err := h.Users.FindByID(r.Context(), resetToken.UserID)
	if err != nil {
		slog.ErrorContext(r.Context(), "password reset: lookup user", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "internal server error")
		return
	}
	if user.PasswordHash == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid or expired reset token")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), auth.BcryptCost)
	if err != nil {
		slog.ErrorContext(r.Context(), "password reset: hash password", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if err := h.Users.UpdatePassword(r.Context(), resetToken.UserID, string(hash)); err != nil {
		slog.ErrorContext(r.Context(), "password reset: update password", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Consume the token — log but don't fail if deletion errors since the
	// password has already been updated successfully.
	if err := h.Resets.DeletePasswordResetToken(r.Context(), resetToken.ID); err != nil {
		slog.ErrorContext(r.Context(), "password reset: consume token", slog.Any("error", err))
	}

	writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: "password reset successfully"})
}
