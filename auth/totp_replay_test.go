package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTOTPUsedCodeCache_WasUsed_notPresent(t *testing.T) {
	var c TOTPUsedCodeCache
	require.False(t, c.WasUsed("user1", "123456"))
}

func TestTOTPUsedCodeCache_MarkUsedAndWasUsed(t *testing.T) {
	var c TOTPUsedCodeCache

	c.MarkUsed("user1", "123456")
	require.True(t, c.WasUsed("user1", "123456"))

	// Different user should not be affected.
	require.False(t, c.WasUsed("user2", "123456"))

	// Different code should not be affected.
	require.False(t, c.WasUsed("user1", "999999"))
}

func TestTOTPUsedCodeCache_WasUsed_expiredEntry(t *testing.T) {
	var c TOTPUsedCodeCache

	// Manually insert an already-expired entry.
	c.entries.Store("user1\x00999999", time.Now().Add(-time.Second))

	// The entry exists in the map but is expired — WasUsed must return false.
	require.False(t, c.WasUsed("user1", "999999"))
}

func TestTOTPUsedCodeCache_MaybeSweep_removesExpired(t *testing.T) {
	var c TOTPUsedCodeCache

	// Force lastSweep far enough in the past that the sweep threshold is crossed.
	c.mu.Lock()
	c.lastSweep = time.Now().Add(-2 * totpReplayWindow)
	c.mu.Unlock()

	// Insert an expired entry directly.
	c.entries.Store("user1\x00111111", time.Now().Add(-time.Second))

	// WasUsed triggers maybeSweep, which should remove the expired entry.
	require.False(t, c.WasUsed("user1", "111111"))

	// The expired key should be gone from the map after the sweep.
	_, present := c.entries.Load("user1\x00111111")
	require.False(t, present)
}

func TestTOTPUsedCodeCache_MaybeSweep_skipsRecentlySwiped(t *testing.T) {
	var c TOTPUsedCodeCache

	// Set lastSweep to just now so the sweep threshold is NOT crossed.
	c.mu.Lock()
	c.lastSweep = time.Now()
	c.mu.Unlock()

	// Insert an expired entry directly.
	c.entries.Store("user1\x00222222", time.Now().Add(-time.Second))

	// WasUsed should still return false for the expired entry (expiry check in WasUsed).
	require.False(t, c.WasUsed("user1", "222222"))

	// Because the sweep was skipped, the key is still in the map.
	_, present := c.entries.Load("user1\x00222222")
	require.True(t, present)
}

func TestTOTPUsedCodeCache_MaybeSweep_keepsLiveEntries(t *testing.T) {
	var c TOTPUsedCodeCache

	// Force an immediate sweep.
	c.mu.Lock()
	c.lastSweep = time.Now().Add(-2 * totpReplayWindow)
	c.mu.Unlock()

	// Insert a live entry.
	c.entries.Store("user1\x00333333", time.Now().Add(totpReplayWindow))

	// Trigger the sweep via WasUsed (the live entry must survive).
	_ = c.WasUsed("user1", "999999")

	_, present := c.entries.Load("user1\x00333333")
	require.True(t, present)
}
