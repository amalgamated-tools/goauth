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

func TestRateLimiter_allowsUpToBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	for i := 0; i < 3; i++ {
		require.Truef(t, rl.allow("key"), "call %d should be allowed within burst", i+1)
	}
}

func TestRateLimiter_deniesAfterBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	for i := 0; i < 3; i++ {
		rl.allow("key")
	}
	require.False(t, rl.allow("key"))
}

func TestRateLimiter_refillsOverTime(t *testing.T) {
	rl := NewRateLimiter(100, 1) // 100 tokens/s
	rl.allow("key")              // consume the only burst token

	// Manually advance the visitor's lastSeen into the past so that the next
	// allow call sees elapsed time.
	rl.mu.Lock()
	rl.visitors["key"].lastSeen = time.Now().Add(-100 * time.Millisecond)
	rl.mu.Unlock()

	require.True(t, rl.allow("key"))
}

func TestRateLimiter_independentKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.allow("a") // exhaust "a"
	require.True(t, rl.allow("b"))
}

func TestRateLimiter_cleanup(t *testing.T) {
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

func TestRateLimiterMiddleware_allow(t *testing.T) {
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

func TestRateLimiterMiddleware_deny(t *testing.T) {
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

func TestRateLimiterWrap_allow(t *testing.T) {
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

func TestRateLimiterWrap_deny(t *testing.T) {
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

func TestParseTrustedProxyCIDRs_empty(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs("")
	require.NoError(t, err)
	require.Nil(t, cidrs)
}

func TestParseTrustedProxyCIDRs_valid(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs("10.0.0.0/8, 192.168.1.0/24")
	require.NoError(t, err)
	require.Len(t, cidrs, 2)
}

func TestParseTrustedProxyCIDRs_skipsBlankParts(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs(",10.0.0.0/8,")
	require.NoError(t, err)
	require.Len(t, cidrs, 1)
}

func TestParseTrustedProxyCIDRs_invalid(t *testing.T) {
	_, err := ParseTrustedProxyCIDRs("not-a-cidr")
	require.Error(t, err)
}

func TestIPFromRequest_splitsRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:4321"

	ip := ipFromRequest(req)
	require.Equal(t, "203.0.113.5", ip)
}

func TestIPFromRequest_noPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5" // no port

	ip := ipFromRequest(req)
	require.Equal(t, "203.0.113.5", ip)
}

func TestIPFromRequest_trustedProxyNoXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0" // trusted proxy

	// No X-Forwarded-For → fall back to direct peer.
	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "10.0.0.1", ip)
}

func TestIPFromRequest_trustedProxyWithXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.2")

	// Walks right-to-left: 10.0.0.2 is trusted → continue; 203.0.113.99 is not → use it.
	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "203.0.113.99", ip)
}

func TestIPFromRequest_untrustedPeerIgnoresXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:0" // NOT in trusted range
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "1.2.3.4", ip)
}

func TestNewRateLimiter_withTrustedProxies(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	rl := NewRateLimiterWithTrustedProxies(5, 10, []*net.IPNet{cidr})
	require.NotNil(t, rl)
	require.Len(t, rl.trustedProxies, 1)
}

func TestIsTrusted_matchesCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")

	require.True(t, isTrusted(net.ParseIP("192.168.1.1"), []*net.IPNet{cidr}))
	require.False(t, isTrusted(net.ParseIP("10.0.0.1"), []*net.IPNet{cidr}))
}

// ---------------------------------------------------------------------------
// ipFromRequestTrusted — additional branch coverage
// ---------------------------------------------------------------------------

func TestIPFromRequestTrusted_allXFFEntriesTrusted(t *testing.T) {
	// All XFF entries fall within the trusted CIDR, so we fall back to the
	// direct peer address (the trusted proxy).
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.3")

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "10.0.0.1", ip)
}

func TestIPFromRequestTrusted_xffHostPortUntrusted(t *testing.T) {
	// XFF contains a host:port entry whose IP is not trusted — it should be
	// returned as the client IP (without the port).
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	req.Header.Set("X-Forwarded-For", "203.0.113.5:12345") // not trusted, has port

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	require.Equal(t, "203.0.113.5", ip)
}

func TestIPFromRequestTrusted_xffHostPortTrusted(t *testing.T) {
	// XFF entry is a trusted host:port. The walk should continue past it.
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	// First real client IP, then a trusted proxy given as host:port.
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.2:8080")

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	// 10.0.0.2 is trusted, so we continue left; 203.0.113.99 is not trusted.
	require.Equal(t, "203.0.113.99", ip)
}

func TestIPFromRequestTrusted_xffInvalidEntry(t *testing.T) {
	// XFF contains a non-IP, non-host:port entry — should be skipped.
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	// bad entry followed by the real untrusted IP
	req.Header.Set("X-Forwarded-For", "203.0.113.10, not-an-ip!!")

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	// "not-an-ip!!" is skipped; 203.0.113.10 is not trusted → use it.
	require.Equal(t, "203.0.113.10", ip)
}

func TestRateLimiter_clientIP_noTrustedProxies(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "5.6.7.8:1234"
	require.Equal(t, "5.6.7.8", rl.clientIP(req))
}

func TestRateLimiter_clientIP_withTrustedProxies(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	rl := NewRateLimiterWithTrustedProxies(1, 1, []*net.IPNet{cidr})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	req.Header.Set("X-Forwarded-For", "5.6.7.8")
	require.Equal(t, "5.6.7.8", rl.clientIP(req))
}
