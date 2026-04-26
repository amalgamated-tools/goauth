package auth

import (
	"context"
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

	// Sessions is an optional SessionStore. When set, the middleware validates
	// the JWT jti claim against the store, enabling server-side session
	// revocation. API key requests bypass session checks.
	Sessions SessionStore
}

type contextKey string

const (
	userIDKey contextKey = "userID"
	rolesKey  contextKey = "roles"
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

// RolesFromContext returns the roles explicitly stored in the context with
// ContextWithRoles. These values reflect whatever roles a middleware or caller
// chose to record for downstream use; they are not guaranteed to be the user's
// complete assigned roles. Returns nil if no roles have been stored.
func RolesFromContext(ctx context.Context) []Role {
	v, _ := ctx.Value(rolesKey).([]Role)
	return v
}

// ContextWithRoles returns a new context with the given caller-supplied roles
// stored for downstream use.
func ContextWithRoles(ctx context.Context, roles []Role) context.Context {
	return context.WithValue(ctx, rolesKey, roles)
}

// tokenSource indicates where a token was extracted from.
type tokenSource int

const (
	tokenSourceNone tokenSource = iota
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

// API key last-used throttling (process-local).
var (
	apiKeyTouchMu       sync.Mutex
	apiKeyLastTouchedAt = make(map[string]time.Time)
)

const apiKeyTouchInterval = 5 * time.Minute

// defaultMiddlewareCacheTTL is the TTL used by AdminMiddleware, RequireRole,
// and RequirePermission for their internal caching checkers.
const defaultMiddlewareCacheTTL = 5 * time.Second

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
// Returns (userID, sessionID, error). sessionID is empty for API key requests.
func resolveUser(ctx context.Context, token string, source tokenSource, jwtMgr *JWTManager, apiKeys APIKeyStore, apiKeyPrefix string) (string, string, error) {
	if apiKeys != nil && apiKeyPrefix != "" && strings.HasPrefix(token, apiKeyPrefix) {
		if source != tokenSourceHeader {
			return "", "", ErrInvalidToken
		}
		keyHash := HashHighEntropyToken(token)
		uid, keyID, err := apiKeys.ValidateAPIKey(ctx, keyHash)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return "", "", ErrInvalidToken
			}
			return "", "", err
		}
		if shouldTouchAPIKeyLastUsed(keyID, time.Now()) {
			if err := apiKeys.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
				slog.WarnContext(ctx, "failed to touch API key last_used_at", slog.Any("error", err))
			}
		}
		return uid, "", nil
	}
	claims, err := jwtMgr.ValidateToken(ctx, token)
	if err != nil {
		return "", "", err
	}
	return claims.UserID, claims.ID, nil
}

// Middleware returns HTTP middleware that validates JWTs and API keys.
func Middleware(jwtMgr *JWTManager, cfg Config, apiKeys APIKeyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := authenticate(w, r, jwtMgr, apiKeys, cfg)
			if !ok {
				return
			}
			ctx := ContextWithUserID(r.Context(), userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminChecker verifies whether a user is an admin.
type AdminChecker interface {
	IsAdmin(ctx context.Context, userID string) (bool, error)
}

type adminCacheEntry struct {
	isAdmin   bool
	expiresAt time.Time
	seq       uint64 // matches the corresponding orderEntry.seq
}

type cachingAdminChecker struct {
	delegate      AdminChecker
	ttl           time.Duration
	mu            sync.RWMutex
	entries       map[string]adminCacheEntry
	order         []orderEntry[string] // insertion-order queue for FIFO eviction
	seq           uint64
	lastSweepTime time.Time
}

func newCachingAdminChecker(delegate AdminChecker, ttl time.Duration) AdminChecker {
	if ttl <= 0 {
		ttl = defaultMiddlewareCacheTTL
	}
	return &cachingAdminChecker{
		delegate: delegate,
		ttl:      ttl,
		entries:  make(map[string]adminCacheEntry),
	}
}

func (c *cachingAdminChecker) sweepEntriesLocked(now time.Time) {
	if now.Sub(c.lastSweepTime) >= cacheSweepInterval {
		c.lastSweepTime = now
		for k, e := range c.entries {
			if !e.expiresAt.After(now) {
				delete(c.entries, k)
			}
		}
	}
	// Always compact so stale re-insertion entries do not accumulate between sweeps,
	// and the eviction loop reliably finds live entries.
	c.order = compactOrderLocked(c.order, func(k string) (uint64, bool) {
		e, ok := c.entries[k]
		return e.seq, ok
	})
	// Evict the oldest-inserted entries first until the cache is under capacity.
	for len(c.entries) >= defaultAdminCacheMaxEntries {
		if len(c.order) == 0 {
			// Compaction removed all stale entries but the map is still at capacity;
			// evict an arbitrary entry to preserve the size bound.
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
			break
		}
		oldest := c.order[0]
		c.order[0] = orderEntry[string]{} // clear before slicing to release GC ref
		c.order = c.order[1:]
		if e, ok := c.entries[oldest.key]; ok && e.seq == oldest.seq {
			delete(c.entries, oldest.key)
		}
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
	c.sweepEntriesLocked(now)
	c.seq++
	c.entries[userID] = adminCacheEntry{isAdmin: isAdmin, expiresAt: now.Add(c.ttl), seq: c.seq}
	c.order = append(c.order, orderEntry[string]{key: userID, seq: c.seq})
	c.mu.Unlock()

	return isAdmin, nil
}

// authenticate extracts and validates the token from r, including optional
// session validation when cfg.Sessions is set. On failure it writes an
// appropriate error response to w and returns ("", false).
func authenticate(w http.ResponseWriter, r *http.Request, jwtMgr *JWTManager, apiKeys APIKeyStore, cfg Config) (string, bool) {
	token, source, reason := extractToken(r, cfg.CookieName)
	if token == "" {
		if reason != "" {
			slog.InfoContext(r.Context(), "authentication required", slog.String("reason", reason))
		}
		jsonError(w, http.StatusUnauthorized, "authentication required")
		return "", false
	}
	userID, sessionID, err := resolveUser(r.Context(), token, source, jwtMgr, apiKeys, cfg.APIKeyPrefix)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpiredToken) {
			jsonError(w, http.StatusUnauthorized, "invalid or expired token")
		} else {
			slog.ErrorContext(r.Context(), "failed to resolve user", slog.Any("error", err))
			jsonError(w, http.StatusInternalServerError, "internal authentication error")
		}
		return "", false
	}
	if cfg.Sessions != nil && sessionID != "" {
		sess, serr := cfg.Sessions.FindSessionByID(r.Context(), sessionID)
		if serr != nil {
			if errors.Is(serr, ErrNotFound) {
				jsonError(w, http.StatusUnauthorized, "session expired or revoked")
			} else {
				slog.ErrorContext(r.Context(), "failed to look up session", slog.Any("error", serr))
				jsonError(w, http.StatusInternalServerError, "internal server error")
			}
			return "", false
		}
		if sess == nil || sess.UserID != userID || time.Now().After(sess.ExpiresAt) {
			jsonError(w, http.StatusUnauthorized, "session expired or revoked")
			return "", false
		}
	}
	return userID, true
}

// AdminMiddleware returns middleware that checks admin privileges.
func AdminMiddleware(jwtMgr *JWTManager, checker AdminChecker, cfg Config, apiKeys APIKeyStore) func(http.Handler) http.Handler {
	cachedChecker := newCachingAdminChecker(checker, defaultMiddlewareCacheTTL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := authenticate(w, r, jwtMgr, apiKeys, cfg)
			if !ok {
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

			ctx := ContextWithUserID(r.Context(), userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that verifies the authenticated user has the
// specified role. The resolved user ID is stored in context via ContextWithUserID.
func RequireRole(jwtMgr *JWTManager, checker RoleChecker, cfg Config, apiKeys APIKeyStore, role Role) func(http.Handler) http.Handler {
	cachedChecker := NewCachingRoleChecker(checker, defaultMiddlewareCacheTTL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := authenticate(w, r, jwtMgr, apiKeys, cfg)
			if !ok {
				return
			}

			hasRole, err := cachedChecker.HasRole(r.Context(), userID, role)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to verify role")
				return
			}
			if !hasRole {
				jsonError(w, http.StatusForbidden, "insufficient role")
				return
			}

			ctx := ContextWithUserID(r.Context(), userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission returns middleware that verifies the authenticated user has
// the specified permission (via any of their assigned roles). The resolved user
// ID is stored in context via ContextWithUserID.
func RequirePermission(jwtMgr *JWTManager, checker RoleChecker, cfg Config, apiKeys APIKeyStore, perm Permission) func(http.Handler) http.Handler {
	cachedChecker := NewCachingRoleChecker(checker, defaultMiddlewareCacheTTL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := authenticate(w, r, jwtMgr, apiKeys, cfg)
			if !ok {
				return
			}

			hasPerm, err := cachedChecker.HasPermission(r.Context(), userID, perm)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "failed to verify permission")
				return
			}
			if !hasPerm {
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
