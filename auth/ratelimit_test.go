package auth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestRateLimiter creates a limiter and resets its nextCleanup to the past
// so the cleanup path is exercised on the first allow call in tests that need it.
func newTestRateLimiter(rate float64, burst int) *RateLimiter {
	rl := NewRateLimiter(rate, burst)
	rl.nextCleanup = time.Now().Add(-time.Second) // force cleanup on next call
	return rl
}

func TestRateLimiterAllowsUpToBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	for i := range 3 {
		require.Truef(t, rl.allow("key"), "call %d should be allowed within burst", i+1)
	}
}

func TestRateLimiterDeniesAfterBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	for range 3 {
		rl.allow("key")
	}
	require.False(t, rl.allow("key"))
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := NewRateLimiter(100, 1) // 100 tokens/s
	rl.allow("key")              // consume the only burst token

	// Manually advance the visitor's lastSeen into the past so that the next
	// allow call sees elapsed time.
	rl.mu.Lock()
	rl.visitors["key"].lastSeen = time.Now().Add(-100 * time.Millisecond)
	rl.mu.Unlock()

	require.True(t, rl.allow("key"))
}

func TestRateLimiterIndependentKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.allow("a") // exhaust "a"
	require.True(t, rl.allow("b"))
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := newTestRateLimiter(10, 5)
	// Add a stale visitor.
	rl.mu.Lock()
	rl.visitors["stale"] = &visitor{tokens: 5, lastSeen: time.Now().Add(-rl.cleanup - time.Second)}
	rl.mu.Unlock()

	// This call should trigger cleanup and remove "stale".
	rl.allow("new-key")

	rl.mu.Lock()
	_, exists := rl.visitors["stale"]
	rl.mu.Unlock()
	require.False(t, exists)
}

func TestRateLimiterMiddlewareAllow(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiterMiddlewareDeny(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	makeReq := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	makeReq() // consumes the burst
	require.Equal(t, http.StatusTooManyRequests, makeReq())
}

func TestRateLimiterWrapAllow(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	wrapped := rl.Wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	w := httptest.NewRecorder()
	wrapped(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiterWrapDeny(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	wrapped := rl.Wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	makeReq := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:80"
		w := httptest.NewRecorder()
		wrapped(w, req)
		return w.Code
	}

	makeReq()
	require.Equal(t, http.StatusTooManyRequests, makeReq())
}

func TestParseTrustedProxyCIDRsEmpty(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs("")
	require.NoError(t, err)
	require.Nil(t, cidrs)
}

func TestParseTrustedProxyCIDRsValid(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs("10.0.0.0/8, 192.168.1.0/24")
	require.NoError(t, err)
	require.Len(t, cidrs, 2)
}

func TestParseTrustedProxyCIDRsSkipsBlankParts(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs(",10.0.0.0/8,")
	require.NoError(t, err)
	require.Len(t, cidrs, 1)
}

func TestParseTrustedProxyCIDRsInvalid(t *testing.T) {
	_, err := ParseTrustedProxyCIDRs("not-a-cidr")
	require.Error(t, err)
}

func TestIPFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:4321"

	ip := ipFromRequest(req)
	require.Equal(t, "203.0.113.5", ip)
}

func TestIPFromRequestNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5" // no port

	ip := ipFromRequest(req)
	require.Equal(t, "203.0.113.5", ip)
}

func TestIPFromRequestTrustedProxyNoXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0" // trusted proxy

	// No X-Forwarded-For → fall back to direct peer.
	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "10.0.0.1", ip)
}

func TestIPFromRequestTrustedProxyWithXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.2")

	// Walks right-to-left: 10.0.0.2 is trusted → continue; 203.0.113.99 is not → use it.
	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "203.0.113.99", ip)
}

func TestIPFromRequestUntrustedPeerIgnoresXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:0" // NOT in trusted range
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "1.2.3.4", ip)
}

func TestNewRateLimiterWithTrustedProxies(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	rl := NewRateLimiterWithTrustedProxies(5, 10, []*net.IPNet{cidr})
	require.NotNil(t, rl)
	require.Len(t, rl.trustedProxies, 1)
}

func TestIsTrusted(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")

	require.True(t, isTrusted(net.ParseIP("192.168.1.1"), []*net.IPNet{cidr}))
	require.False(t, isTrusted(net.ParseIP("10.0.0.1"), []*net.IPNet{cidr}))
}
