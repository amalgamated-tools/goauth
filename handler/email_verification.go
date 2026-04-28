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

const (
	defaultVerificationTokenTTL = 24 * time.Hour
	// 32 random bytes = 64 hex chars = 256 bits of entropy.
	verificationTokenBytes = 32

	verificationOKMessage = "if that address is registered, a verification email has been sent"
)

// EmailVerificationHandler holds dependencies for email verification endpoints.
//
// SendEmail is called with the recipient address and the plaintext token.
// Consuming applications are responsible for formatting the email body and
// sending it via the smtp package (or any other mechanism).
// If SendEmail is nil, SendVerification returns HTTP 503 before any database
// write, treating a missing sender as a misconfiguration error.
type EmailVerificationHandler struct {
	Users         auth.UserStore
	Verifications auth.EmailVerificationStore
	// SendEmail sends a verification email to the given address. The token
	// argument is the plaintext token to embed in the verification link.
	SendEmail func(ctx context.Context, to, token string) error
	// TokenTTL is how long a verification token is valid. Defaults to 24 hours.
	TokenTTL time.Duration
}

func (h *EmailVerificationHandler) tokenTTL() time.Duration {
	if h.TokenTTL > 0 {
		return h.TokenTTL
	}
	return defaultVerificationTokenTTL
}

type sendVerificationRequest struct {
	Email string `json:"email"`
}

// SendVerification creates a verification token for the given email address
// and calls SendEmail if configured. Returns 503 if SendEmail is nil
// (misconfiguration); otherwise always returns 200 to avoid leaking whether
// an address is registered.
//
// Route: POST /verify-email/send
func (h *EmailVerificationHandler) SendVerification(w http.ResponseWriter, r *http.Request) {
	var req sendVerificationRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "email is required")
		return
	}

	if h.SendEmail == nil {
		writeError(r.Context(), w, http.StatusServiceUnavailable, "email verification sending is not configured")
		return
	}

	// Look up user – always return 200 even when not found to avoid
	// leaking account existence.
	user, err := h.Users.FindByEmail(r.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, auth.ErrNotFound) {
			slog.ErrorContext(r.Context(), "failed to find user for email verification", slog.Any("error", err))
		}
		writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: verificationOKMessage})
		return
	}

	if user.EmailVerified {
		writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: verificationOKMessage})
		return
	}

	plaintext, err := auth.GenerateRandomHex(verificationTokenBytes)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to generate verification token", slog.Any("error", err))
		writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: verificationOKMessage})
		return
	}
	tokenHash := auth.HashHighEntropyToken(plaintext)

	if _, err := h.Verifications.CreateEmailVerification(r.Context(), user.ID, tokenHash, time.Now().UTC().Add(h.tokenTTL())); err != nil {
		slog.ErrorContext(r.Context(), "failed to store verification token", slog.Any("error", err))
		writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: verificationOKMessage})
		return
	}

	if err := h.SendEmail(r.Context(), user.Email, plaintext); err != nil {
		slog.ErrorContext(r.Context(), "failed to send verification email", slog.String("userID", user.ID), slog.Any("error", err))
	}

	writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: verificationOKMessage})
}

// VerifyEmail consumes a verification token from the query string and marks
// the associated user's email address as verified.
//
// Route: GET /verify-email?token=<plaintext-token>
func (h *EmailVerificationHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	plaintext := strings.TrimSpace(r.URL.Query().Get("token"))
	if plaintext == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "token is required")
		return
	}

	tokenHash := auth.HashHighEntropyToken(plaintext)
	record, err := h.Verifications.ConsumeEmailVerification(r.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusBadRequest, "invalid or expired verification token")
			return
		}
		slog.ErrorContext(r.Context(), "failed to consume verification token", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to verify email")
		return
	}

	if time.Now().UTC().After(record.ExpiresAt) {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid or expired verification token")
		return
	}

	if err := h.Verifications.SetEmailVerified(r.Context(), record.UserID); err != nil {
		slog.ErrorContext(r.Context(), "failed to mark email as verified", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to verify email")
		return
	}

	writeJSON(r.Context(), w, http.StatusOK, messageBody{Message: "email verified"})
}
