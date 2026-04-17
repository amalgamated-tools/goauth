package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures the auth middleware behavior.
type Config struct {
	// CookieName is the name of the HttpOnly auth cookie. Required.
	CookieName string

	// APIKeyPrefix is the string prefix for API keys (e.g. "bib_", "sch_").
	// If empty, API key authentication is disabled in the middleware.
	APIKeyPrefix string
}

type contextKey string

const (
	userIDKey  contextKey = "userID"
	rolesKey   contextKey = "roles"
)

// UserIDFromContext extracts the user ID set by the auth middleware.
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey).(string)
	return v
}

// ContextWithUserID returns a new context with the given user ID set.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// RolesFromContext returns the roles set by RequireRole or RequirePermission
// middleware. Returns nil if no roles have been stored in the context.
func RolesFromContext(ctx context.Context) []Role {
	v, _ := ctx.Value(rolesKey).([]Role)
	return v
}

// ContextWithRoles returns a new context with the given roles set.
func ContextWithRoles(ctx context.Context, roles []Role) context.Context {
	return context.WithValue(ctx, rolesKey, roles)
}

// tokenSource indicates where a token was extracted from.
type tokenSource int

const (
	tokenSourceNone   tokenSource = iota
	tokenSourceHeader
	tokenSourceCookie
)

func extractToken(r *http.Request, cookieName string) (string, tokenSource, string) {
	if header := r.Header.Get("Authorization"); header != "" {
		header = strings.TrimSpace(header)
		if after, ok := strings.CutPrefix(header, "Bearer "); ok {
			token := strings.TrimSpace(after)
			if token != "" {
				return token, tokenSourceHeader, ""
			}
		}
	}
	if cookieName != "" {
		if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
			return c.Value, tokenSourceCookie, ""
		}
	}
	return "", tokenSourceNone, "missing token"
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// API key last-used throttling (process-local).
var (
	apiKeyTouchMu       sync.Mutex
	apiKeyLastTouchedAt = make(map[string]time.Time)
)

const apiKeyTouchInterval = 5 * time.Minute

func shouldTouchAPIKeyLastUsed(id string, now time.Time) bool {
	apiKeyTouchMu.Lock()
	defer apiKeyTouchMu.Unlock()

	last, ok := apiKeyLastTouchedAt[id]
	if ok && now.Sub(last) < apiKeyTouchInterval {
		return false
	}
	apiKeyLastTouchedAt[id] = now

	const sweepThreshold = 100
	if len(apiKeyLastTouchedAt) >= sweepThreshold {
		for k, v := range apiKeyLastTouchedAt {
			if now.Sub(v) >= apiKeyTouchInterval {
				delete(apiKeyLastTouchedAt, k)
			}
		}
	}
	return true
}

// resolveUser determines the user ID from the given token. If the token starts
// with the API key prefix and came from the Authorization header, it's validated
// as an API key. Otherwise it's validated as a JWT.
func resolveUser(ctx context.Context, token string, source tokenSource, jwtMgr *JWTManager, apiKeys APIKeyStore, apiKeyPrefix string) (string, error) {
	if apiKeys != nil && apiKeyPrefix != "" && strings.HasPrefix(token, apiKeyPrefix) {
		if source != tokenSourceHeader {
			return "", ErrInvalidToken
		}
		keyHash := HashHighEntropyToken(token)
		uid, keyID, err := apiKeys.ValidateAPIKey(ctx, keyHash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", ErrInvalidToken
			}
			return "", err
		}
		if shouldTouchAPIKeyLastUsed(keyID, time.Now()) {
			if err := apiKeys.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
				slog.WarnContext(ctx, "failed to touch API key last_used_at", slog.Any("error", err))
			}
		}
		return uid, nil
	}
	claims, err := jwtMgr.ValidateToken(ctx, token)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

// Middleware returns HTTP middleware that validates JWTs and API keys.
func Middleware(jwtMgr *JWTManager, cfg Config, apiKeys APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, source, reason := extractToken(r, cfg.CookieName)
			if token == "" {
				if reason != "" {
					slog.InfoContext(r.Context(), "authentication required", slog.String("reason", reason))
				}
				jsonError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := resolveUser(r.Context(), token, source, jwtMgr, apiKeys, cfg.APIKeyPrefix)
			if err != nil {
				if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken) {
					jsonError(w, http.StatusUnauthorized, "invalid or expired token")
				} else {
					slog.ErrorContext(r.Context(), "failed to resolve user", slog.Any("error", err))
					jsonError(w, http.StatusInternalServerError, "internal server error")
				}
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminChecker verifies whether a user is an admin.
type AdminChecker interface {
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type cachingAdminChecker struct {
	delegate AdminChecker
	ttl      time.Duration
	mu       sync.RWMutex
	entries  map[string]struct {
		isAdmin   bool
		expiresAt time.Time
	}
}

func newCachingAdminChecker(delegate AdminChecker, ttl time.Duration) AdminChecker {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &cachingAdminChecker{
		delegate: delegate,
		ttl:      ttl,
		entries: make(map[string]struct {
			isAdmin   bool
			expiresAt time.Time
		}),
	}
}

func (c *cachingAdminChecker) IsAdmin(ctx context.Context, userID string) (bool, error) {
	now := time.Now()
	c.mu.RLock()
	entry, ok := c.entries[userID]
	c.mu.RUnlock()

	if ok && now.Before(entry.expiresAt) {
		return entry.isAdmin, nil
	}

	isAdmin, err := c.delegate.IsAdmin(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("admin check failed: %w", err)
	}

	c.mu.Lock()
	c.entries[userID] = struct {
		isAdmin   bool
		expiresAt time.Time
	}{isAdmin: isAdmin, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()

	return isAdmin, nil
}

// AdminMiddleware returns middleware that checks admin privileges.
func AdminMiddleware(jwtMgr *JWTManager, checker AdminChecker, cfg Config, apiKeys APIKeyStore) func(http.Handler) http.Handler {
	cachedChecker := newCachingAdminChecker(checker, 5*time.Second)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, source, _ := extractToken(r, cfg.CookieName)
			if token == "" {
				jsonError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := resolveUser(r.Context(), token, source, jwtMgr, apiKeys, cfg.APIKeyPrefix)
			if err != nil {
				if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken) {
					jsonError(w, http.StatusUnauthorized, "invalid or expired token")
				} else {
					jsonError(w, http.StatusInternalServerError, "internal authentication error")
				}
				return
			}

			isAdmin, err := cachedChecker.IsAdmin(r.Context(), userID)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to verify permissions")
				return
			}
			if !isAdmin {
				jsonError(w, http.StatusForbidden, "admin access required")
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that verifies the authenticated user has the
// specified role. It resolves the token identically to AdminMiddleware and
// stores the user's roles in the request context via ContextWithRoles.
func RequireRole(jwtMgr *JWTManager, checker RoleChecker, cfg Config, apiKeys APIKeyStore, role Role) func(http.Handler) http.Handler {
	cachedChecker := NewCachingRoleChecker(checker, 5*time.Second)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, source, _ := extractToken(r, cfg.CookieName)
			if token == "" {
				jsonError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := resolveUser(r.Context(), token, source, jwtMgr, apiKeys, cfg.APIKeyPrefix)
			if err != nil {
				if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken) {
					jsonError(w, http.StatusUnauthorized, "invalid or expired token")
				} else {
					jsonError(w, http.StatusInternalServerError, "internal authentication error")
				}
				return
			}

			ok, err := cachedChecker.HasRole(r.Context(), userID, role)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to verify role")
				return
			}
			if !ok {
				jsonError(w, http.StatusForbidden, "insufficient role")
				return
			}

			ctx := ContextWithUserID(r.Context(), userID)
			ctx = ContextWithRoles(ctx, []Role{role})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission returns middleware that verifies the authenticated user has
// the specified permission (via any of their assigned roles).
func RequirePermission(jwtMgr *JWTManager, checker RoleChecker, cfg Config, apiKeys APIKeyStore, perm Permission) func(http.Handler) http.Handler {
	cachedChecker := NewCachingRoleChecker(checker, 5*time.Second)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, source, _ := extractToken(r, cfg.CookieName)
			if token == "" {
				jsonError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := resolveUser(r.Context(), token, source, jwtMgr, apiKeys, cfg.APIKeyPrefix)
			if err != nil {
				if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken) {
					jsonError(w, http.StatusUnauthorized, "invalid or expired token")
				} else {
					jsonError(w, http.StatusInternalServerError, "internal authentication error")
				}
				return
			}

			ok, err := cachedChecker.HasPermission(r.Context(), userID, perm)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to verify permission")
				return
			}
			if !ok {
				jsonError(w, http.StatusForbidden, "insufficient permission")
				return
			}

			ctx := ContextWithUserID(r.Context(), userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// adminCheckerFromRoleChecker adapts a RoleChecker to satisfy AdminChecker by
// mapping the RoleAdmin role to the IsAdmin result.
type adminCheckerFromRoleChecker struct {
	rc RoleChecker
}

// NewAdminCheckerFromRoleChecker returns an AdminChecker that delegates to rc,
// treating users with RoleAdmin as admins. This lets consumers who have adopted
// RoleChecker continue to use AdminMiddleware without duplicating logic.
func NewAdminCheckerFromRoleChecker(rc RoleChecker) AdminChecker {
	return &adminCheckerFromRoleChecker{rc: rc}
}

func (a *adminCheckerFromRoleChecker) IsAdmin(ctx context.Context, userID string) (bool, error) {
	return a.rc.HasRole(ctx, userID, RoleAdmin)
}
