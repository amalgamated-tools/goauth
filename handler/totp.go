package handler

import (
	"encoding/base32"
	"errors"
	"log/slog"
	"net/http"

	"github.com/amalgamated-tools/goauth/auth"
)

// TOTPHandler provides HTTP handlers for TOTP/MFA enrollment and verification.
//
// Enrollment flow:
//  1. POST /totp/generate  — server generates a secret and provisioning URI;
//     the client displays the QR code to the user.
//  2. POST /totp/enroll    — client submits the secret together with the first
//     code from the authenticator app; server verifies and persists the secret.
//
// Ongoing use:
//   - POST /totp/verify — validate a code against the enrolled secret.
//   - GET  /totp/status — check whether TOTP is enrolled.
//   - DELETE /totp      — remove the enrolled TOTP secret.
type TOTPHandler struct {
	TOTP      auth.TOTPStore
	Users     auth.UserStore
	Issuer    string
	UsedCodes auth.TOTPUsedCodeCache // required for replay protection; zero value is ready to use
}

type totpGenerateResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

type totpEnrollRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

type totpVerifyRequest struct {
	Code string `json:"code"`
}

// Status reports whether TOTP is enrolled for the authenticated user.
func (h *TOTPHandler) Status(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	_, err := h.TOTP.GetTOTPSecret(r.Context(), userID)
	if err != nil && !errors.Is(err, auth.ErrTOTPNotFound) {
		slog.ErrorContext(r.Context(), "failed to fetch TOTP status", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to fetch TOTP status")
		return
	}
	enrolled := err == nil
	writeJSON(r.Context(), w, http.StatusOK, map[string]bool{"enrolled": enrolled})
}

// Generate creates a fresh TOTP secret and returns it with a provisioning URI
// for QR-code display. The secret is NOT persisted; call Enroll to save it
// after the user has confirmed their authenticator app is working.
func (h *TOTPHandler) Generate(w http.ResponseWriter, r *http.Request) {
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to generate TOTP secret", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	user, err := h.Users.FindByID(r.Context(), userID)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	uri := auth.TOTPProvisioningURI(secret, user.Email, h.Issuer)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(r.Context(), w, http.StatusOK, totpGenerateResponse{
		Secret:          secret,
		ProvisioningURI: uri,
	})
}

// Enroll saves a TOTP secret after verifying that the supplied code is valid.
// The client must send back the secret that was returned by Generate together
// with the current 6-digit code from their authenticator app.
func (h *TOTPHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	var req totpEnrollRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	if req.Secret == "" || req.Code == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "secret and code are required")
		return
	}

	secretBytes, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(req.Secret)
	if decErr != nil || len(secretBytes) < 20 {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid TOTP secret")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	if h.UsedCodes.WasUsed(userID, req.Code) {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	ok, err := auth.ValidateTOTP(req.Secret, req.Code)
	if err != nil {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid TOTP secret")
		return
	}
	if !ok {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	if _, err := h.TOTP.CreateTOTPSecret(r.Context(), userID, req.Secret); err != nil {
		slog.ErrorContext(r.Context(), "failed to save TOTP secret", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to save TOTP secret")
		return
	}
	h.UsedCodes.MarkUsed(userID, req.Code)

	writeJSON(r.Context(), w, http.StatusOK, map[string]bool{"enrolled": true})
}

// Verify checks a TOTP code against the user's enrolled secret.
func (h *TOTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req totpVerifyRequest
	if !decodeJSON(r, w, &req) {
		return
	}
	if req.Code == "" {
		writeError(r.Context(), w, http.StatusBadRequest, "code is required")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	if h.UsedCodes.WasUsed(userID, req.Code) {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	stored, err := h.TOTP.GetTOTPSecret(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrTOTPNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "TOTP not configured")
			return
		}
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to fetch TOTP secret")
		return
	}

	ok, err := auth.ValidateTOTP(stored.Secret, req.Code)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to validate TOTP code")
		return
	}
	if !ok {
		writeError(r.Context(), w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}
	h.UsedCodes.MarkUsed(userID, req.Code)

	writeJSON(r.Context(), w, http.StatusOK, map[string]bool{"valid": true})
}

// Disable removes the enrolled TOTP secret for the authenticated user.
func (h *TOTPHandler) Disable(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if err := h.TOTP.DeleteTOTPSecret(r.Context(), userID); err != nil {
		if errors.Is(err, auth.ErrTOTPNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, "TOTP not configured")
			return
		}
		slog.ErrorContext(r.Context(), "failed to delete TOTP secret", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to disable TOTP")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
