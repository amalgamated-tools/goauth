// Package handler provides HTTP handlers for authentication flows.
// Handlers use standard net/http types and are router-agnostic.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// writeJSON sends a JSON response with the given status code.
func writeJSON(ctx context.Context, w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.ErrorContext(ctx, "failed to encode JSON response", slog.Any("error", err))
	}
}

// writeError sends a JSON error response.
func writeError(ctx context.Context, w http.ResponseWriter, status int, message string) {
	writeJSON(ctx, w, status, map[string]string{"error": message})
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

// tokenFromRequest extracts a bearer or cookie token from the request.
func tokenFromRequest(r *http.Request, cookieName string) string {
	if header := r.Header.Get("Authorization"); header != "" {
		header = strings.TrimSpace(header)
		if after, ok := strings.CutPrefix(header, "Bearer "); ok {
			if tok := strings.TrimSpace(after); tok != "" {
				return tok
			}
		}
	}
	if cookieName != "" {
		if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}
