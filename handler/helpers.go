// Package handler provides HTTP handlers for authentication flows.
// Handlers use standard net/http types and are router-agnostic.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

// tokenCreator is the subset of auth.JWTManager used during token issuance.
type tokenCreator interface {
	CreateToken(ctx context.Context, userID string) (string, error)
	CreateTokenWithSession(ctx context.Context, userID, sessionID string) (string, error)
}

// issueTokens creates an access JWT and, when sessions is non-nil, a session
// record with a refresh token. It writes auth/refresh cookies and returns the
// tokens for inclusion in the response body. On any error it writes an HTTP
// error response and returns false.
func issueTokens(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
	sessions auth.SessionStore,
	jwtMgr tokenCreator,
	cookieName string,
	secureCookies bool,
	refreshCookieName string,
	refreshTokenTTL time.Duration,
) (accessToken, refreshToken string, ok bool) {
	if sessions != nil {
		rawRefresh, err := auth.GenerateRandomHex(32)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to generate refresh token", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create session")
			return "", "", false
		}
		refreshHash := auth.HashHighEntropyToken(rawRefresh)

		ttl := refreshTokenTTL
		if ttl <= 0 {
			ttl = DefaultRefreshTokenTTL
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		sess, err := sessions.CreateSession(r.Context(), userID, refreshHash,
			r.UserAgent(), ip, time.Now().Add(ttl))
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to create session", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create session")
			return "", "", false
		}

		accessToken, err = jwtMgr.CreateTokenWithSession(r.Context(), userID, sess.ID)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to create token", slog.Any("error", err))
			_ = sessions.DeleteSession(r.Context(), sess.ID, userID)
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
			return "", "", false
		}

		if refreshCookieName != "" {
			SetRefreshCookie(w, rawRefresh, refreshCookieName, secureCookies, int(ttl.Seconds()))
		}
		SetAuthCookie(w, accessToken, cookieName, secureCookies)
		return accessToken, rawRefresh, true
	}

	var err error
	accessToken, err = jwtMgr.CreateToken(r.Context(), userID)
	if err != nil {
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
		return "", "", false
	}
	SetAuthCookie(w, accessToken, cookieName, secureCookies)
	return accessToken, "", true
}

// writeJSON sends a JSON response with the given status code.
func writeJSON(ctx context.Context, w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.ErrorContext(ctx, "failed to encode JSON response", slog.Any("error", err))
	}
}

// errorBody is used instead of map[string]string to avoid allocating a map
// for each error response.
type errorBody struct {
	Error string `json:"error"`
}

// messageBody is used instead of map[string]string to avoid allocating a map
// for each success response that carries only a human-readable message.
type messageBody struct {
	Message string `json:"message"`
}

// writeError sends a JSON error response.
func writeError(ctx context.Context, w http.ResponseWriter, status int, message string) {
	writeJSON(ctx, w, status, errorBody{Error: message})
}

// decodeJSON reads and decodes the JSON request body.
func decodeJSON(r *http.Request, w http.ResponseWriter, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(r.Context(), w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

const (
	minPasswordLength = 8
	maxPasswordLength = 72
)

func validatePassword(ctx context.Context, w http.ResponseWriter, password string) bool {
	if len(password) < minPasswordLength {
		writeError(ctx, w, http.StatusBadRequest, fmt.Sprintf("password must be at least %d bytes", minPasswordLength))
		return false
	}
	if len(password) > maxPasswordLength {
		writeError(ctx, w, http.StatusBadRequest, fmt.Sprintf("password must be at most %d bytes", maxPasswordLength))
		return false
	}
	return true
}

// SetAuthCookie sets an HttpOnly auth cookie.
func SetAuthCookie(w http.ResponseWriter, token, cookieName string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/",
		MaxAge: 0, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
}

// ClearAuthCookie removes the auth cookie.
func ClearAuthCookie(w http.ResponseWriter, cookieName string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
}

// SetRefreshCookie sets an HttpOnly refresh token cookie.
func SetRefreshCookie(w http.ResponseWriter, token, cookieName string, secure bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/",
		MaxAge: maxAge, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
}

// ClearRefreshCookie removes the refresh token cookie.
func ClearRefreshCookie(w http.ResponseWriter, cookieName string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
	})
}
