package auth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	for i := 0; i < 3; i++ {
		if !rl.allow("key") {
			t.Errorf("call %d should be allowed within burst", i+1)
		}
	}
}

func TestRateLimiterDeniesAfterBurst(t *testing.T) {
	rl := NewRateLimiter(1, 3)
	for i := 0; i < 3; i++ {
		rl.allow("key")
	}
	if rl.allow("key") {
		t.Error("call after burst is exhausted should be denied")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := NewRateLimiter(100, 1) // 100 tokens/s
	rl.allow("key")              // consume the only burst token

	// Manually advance the visitor's lastSeen into the past so that the next
	// allow call sees elapsed time.
	rl.mu.Lock()
	rl.visitors["key"].lastSeen = time.Now().Add(-100 * time.Millisecond)
	rl.mu.Unlock()

	if !rl.allow("key") {
		t.Error("token should have refilled after elapsed time")
	}
}

func TestRateLimiterIndependentKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.allow("a") // exhaust "a"
	if !rl.allow("b") {
		t.Error("key b should be independent of key a")
	}
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
	if exists {
		t.Error("stale visitor should have been removed during cleanup")
	}
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
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
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", code)
	}
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
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
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", code)
	}
}

func TestParseTrustedProxyCIDRsEmpty(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cidrs != nil {
		t.Error("expected nil for empty input")
	}
}

func TestParseTrustedProxyCIDRsValid(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs("10.0.0.0/8, 192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(cidrs))
	}
}

func TestParseTrustedProxyCIDRsSkipsBlankParts(t *testing.T) {
	cidrs, err := ParseTrustedProxyCIDRs(",10.0.0.0/8,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 {
		t.Errorf("expected 1 CIDR, got %d", len(cidrs))
	}
}

func TestParseTrustedProxyCIDRsInvalid(t *testing.T) {
	_, err := ParseTrustedProxyCIDRs("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIPFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:4321"

	ip := ipFromRequest(req)
	if ip != "203.0.113.5" {
		t.Errorf("expected %q, got %q", "203.0.113.5", ip)
	}
}

func TestIPFromRequestNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5" // no port

	ip := ipFromRequest(req)
	if ip != "203.0.113.5" {
		t.Errorf("expected %q, got %q", "203.0.113.5", ip)
	}
}

func TestIPFromRequestTrustedProxyNoXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0" // trusted proxy

	// No X-Forwarded-For → fall back to direct peer.
	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	if ip != "10.0.0.1" {
		t.Errorf("expected %q, got %q", "10.0.0.1", ip)
	}
}

func TestIPFromRequestTrustedProxyWithXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:0"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.2")

	// Walks right-to-left: 10.0.0.2 is trusted → continue; 203.0.113.99 is not → use it.
	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	if ip != "203.0.113.99" {
		t.Errorf("expected %q, got %q", "203.0.113.99", ip)
	}
}

func TestIPFromRequestUntrustedPeerIgnoresXFF(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:0" // NOT in trusted range
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	ip := ipFromRequestTrusted(req, []*net.IPNet{trusted})
	if ip != "1.2.3.4" {
		t.Errorf("expected direct peer %q, got %q", "1.2.3.4", ip)
	}
}

func TestNewRateLimiterWithTrustedProxies(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	rl := NewRateLimiterWithTrustedProxies(5, 10, []*net.IPNet{cidr})
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
	if len(rl.trustedProxies) != 1 {
		t.Errorf("expected 1 trusted proxy, got %d", len(rl.trustedProxies))
	}
}

func TestIsTrusted(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")

	if !isTrusted(net.ParseIP("192.168.1.1"), []*net.IPNet{cidr}) {
		t.Error("192.168.1.1 should be trusted")
	}
	if isTrusted(net.ParseIP("10.0.0.1"), []*net.IPNet{cidr}) {
		t.Error("10.0.0.1 should not be trusted")
	}
}
