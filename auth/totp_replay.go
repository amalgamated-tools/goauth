package auth

import (
	"sync"
	"time"
)

// totpReplayWindow is the duration for which a used TOTP code is remembered.
// It matches (2*totpSkew+1)*totpPeriod so that every code that ValidateTOTP
// could accept is covered.
const totpReplayWindow = (2*totpSkew + 1) * totpPeriod * time.Second

// TOTPUsedCodeCache is a short-lived in-process cache that records TOTP codes
// that have already been validated, preventing replay attacks within the
// validity window. Expired entries are swept lazily on each WasUsed call,
// at most once per replay window.
//
// The zero value is ready to use.
type TOTPUsedCodeCache struct {
	mu        sync.Mutex
	entries   sync.Map  // key: "userID\x00code", value: time.Time (expiry)
	lastSweep time.Time // guarded by mu
}

// sweep removes expired entries. It is called at most once per replay window.
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
	v, ok := c.entries.Load(userID + "\x00" + code)
	if !ok {
		return false
	}
	return time.Now().Before(v.(time.Time))
}

// MarkUsed records that code was used for userID, blocking its reuse for the
// duration of the replay window.
func (c *TOTPUsedCodeCache) MarkUsed(userID, code string) {
	c.entries.Store(userID+"\x00"+code, time.Now().Add(totpReplayWindow))
}
