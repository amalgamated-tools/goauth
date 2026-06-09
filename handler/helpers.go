// Package handler provides HTTP handlers for authentication flows.
// Handlers use standard net/http types and are router-agnostic.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/amalgamated-tools/goauth/auth"
)

// tokenCreator is the subset of auth.JWTManager used during token issuance.
type tokenCreator interface {
	CreateToken(userID string) (string, error)
	CreateTokenWithSession(userID, sessionID string) (string, error)
}

func requireField(handlerName, fieldName string, value any) error {
	if value == nil {
		return fmt.Errorf("%s misconfigured: %s is required", handlerName, fieldName)
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		if rv.IsNil() {
			return fmt.Errorf("%s misconfigured: %s is required", handlerName, fieldName)
		}
	}
	return nil
}

func validateSessionConfig(handlerName string, sessions auth.SessionStore, refreshCookieName string) error {
	if sessions != nil && refreshCookieName == "" {
		return fmt.Errorf("%s misconfigured: Sessions requires RefreshCookieName", handlerName)
	}
	return nil
}

// logOrDefault returns the given logger, falling back to slog.Default() when it
// is nil.
func logOrDefault(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}

func deleteUserResource(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	paramFunc func(*http.Request, string) string,
	invalidIDMessage string,
	notFoundMessage string,
	logMessage string,
	internalMessage string,
	del func(ctx context.Context, id, userID string) error,
) {
	id := paramFunc(r, "id")
	if id == "" {
		writeError(r.Context(), w, http.StatusBadRequest, invalidIDMessage)
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	if err := del(r.Context(), id, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(r.Context(), w, http.StatusNotFound, notFoundMessage)
			return
		}
		logOrDefault(logger).ErrorContext(r.Context(), logMessage, slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, internalMessage)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	if sessions != nil && refreshCookieName == "" {
		slog.ErrorContext(r.Context(), "issueTokens: Sessions is set but RefreshCookieName is empty — call Validate() at startup")
		writeError(r.Context(), w, http.StatusInternalServerError, "server misconfiguration")
		return "", "", false
	}
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
			r.UserAgent(), ip, time.Now().UTC().Add(ttl))
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to create session", slog.Any("error", err))
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create session")
			return "", "", false
		}

		accessToken, err = jwtMgr.CreateTokenWithSession(userID, sess.ID)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to create token", slog.Any("error", err))
			_ = sessions.DeleteSession(r.Context(), sess.ID, userID)
			writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
			return "", "", false
		}

		SetRefreshCookie(w, rawRefresh, refreshCookieName, secureCookies, int(ttl.Seconds()))
		SetAuthCookie(w, accessToken, cookieName, secureCookies)
		return accessToken, rawRefresh, true
	}

	var err error
	accessToken, err = jwtMgr.CreateToken(userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to create token", slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, "failed to create token")
		return "", "", false
	}
	SetAuthCookie(w, accessToken, cookieName, secureCookies)
	return accessToken, "", true
}

// listUserResources is a generic helper that fetches a list of resources for
// the authenticated user, converts each item to a DTO, and writes the result
// as a JSON response. It centralises the fetch-convert-respond pattern shared
// by APIKeyHandler.List, SessionHandler.List, and PasskeyHandler.ListCredentials.
func listUserResources[T any, D any](
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
	logMsg string,
	userMsg string,
	fetch func(ctx context.Context, userID string) ([]T, error),
	toDTO func(T) D,
) {
	userID := auth.UserIDFromContext(r.Context())
	items, err := fetch(r.Context(), userID)
	if err != nil {
		logOrDefault(logger).ErrorContext(r.Context(), logMsg, slog.Any("error", err))
		writeError(r.Context(), w, http.StatusInternalServerError, userMsg)
		return
	}
	dtos := make([]D, len(items))
	for i, item := range items {
		dtos[i] = toDTO(item)
	}
	writeJSON(r.Context(), w, http.StatusOK, dtos)
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

// nonceBody is used instead of map[string]string to avoid a map allocation on
// nonce response paths shared by OAuth2 and OIDC handlers.
type nonceBody struct {
	Nonce string `json:"nonce"`
}

// writeError sends a JSON error response.
func writeError(ctx context.Context, w http.ResponseWriter, status int, message string) {
	writeJSON(ctx, w, status, errorBody{Error: message})
}

// setNoCacheHeaders prevents browsers and proxies from caching sensitive auth responses.
func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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

var (
	msgPasswordTooShort = fmt.Sprintf("password must be at least %d bytes", minPasswordLength)
	msgPasswordTooLong  = fmt.Sprintf("password must be at most %d bytes", maxPasswordLength)
)

func validatePassword(ctx context.Context, w http.ResponseWriter, password string) bool {
	if len(password) < minPasswordLength {
		writeError(ctx, w, http.StatusBadRequest, msgPasswordTooShort)
		return false
	}
	if len(password) > maxPasswordLength {
		writeError(ctx, w, http.StatusBadRequest, msgPasswordTooLong)
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
