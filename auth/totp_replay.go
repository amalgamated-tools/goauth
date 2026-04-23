package auth

import (
	"sync"
	"time"
)

// totpReplayWindow is the duration for which a used TOTP code is remembered.
// It matches (2*totpSkew+1)*totpPeriod so that every code that ValidateTOTP
// could accept is covered.
const totpReplayWindow = (2*totpSkew + 1) * totpPeriod * time.Second

// totpCacheKey is the composite key used in TOTPUsedCodeCache.entries.
// Using a struct instead of a concatenated string avoids allocating a new
// backing array (~43 bytes for a UUID userID + separator + 6-digit code)
// on every WasUsed and MarkUsed call.
type totpCacheKey struct {
	userID string
	code   string
}

// TOTPUsedCodeCache is a short-lived in-process cache that records TOTP codes
// that have already been validated, preventing replay attacks within the
// validity window. Expired entries are swept lazily on each WasUsed call,
// at most once per replay window.
//
// The zero value is ready to use.
type TOTPUsedCodeCache struct {
	mu        sync.Mutex
	entries   sync.Map  // key: totpCacheKey, value: time.Time (expiry)
	lastSweep time.Time // guarded by mu
}

// maybeSweep removes expired entries when enough time has passed since the
// last sweep. It is called at most once per replay window.
func (c *TOTPUsedCodeCache) maybeSweep() {
	now := time.Now()
	c.mu.Lock()
	if now.Sub(c.lastSweep) < totpReplayWindow {
		c.mu.Unlock()
		return
	}
	c.lastSweep = now
	c.mu.Unlock()

	c.entries.Range(func(k, v any) bool {
		if now.After(v.(time.Time)) {
			c.entries.Delete(k)
		}
		return true
	})
}

// WasUsed reports whether code has already been used for userID within the
// replay window.
func (c *TOTPUsedCodeCache) WasUsed(userID, code string) bool {
	c.maybeSweep()
	v, ok := c.entries.Load(totpCacheKey{userID, code})
	if !ok {
		return false
	}
	return time.Now().Before(v.(time.Time))
}

// MarkUsed records that code was used for userID, blocking its reuse for the
// duration of the replay window. Sweep is intentionally not called here; lazy
// cleanup on WasUsed is sufficient for the expected read-heavy verification
// workload (each login verifies once, rarely enrolls).
func (c *TOTPUsedCodeCache) MarkUsed(userID, code string) {
	c.entries.Store(totpCacheKey{userID, code}, time.Now().Add(totpReplayWindow))
}
