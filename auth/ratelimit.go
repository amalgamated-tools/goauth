package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type visitor struct {
	tokens   float64
	lastSeen time.Time
}

// DefaultRateLimiterMaxVisitors is the default maximum number of unique IP
// addresses tracked concurrently. When the cap is reached, requests from
// previously-unseen IPs are denied without growing the map, bounding memory
// and GC pressure under IP-flood conditions.
const DefaultRateLimiterMaxVisitors = 10_000

// RateLimiter implements a per-IP token-bucket rate limiter.
type RateLimiter struct {
	mu             sync.Mutex
	visitors       map[string]*visitor
	nextCleanup    time.Time
	rate           float64
	burst          int
	cleanup        time.Duration
	maxVisitors    int
	trustedProxies []*net.IPNet
}

// NewRateLimiter creates a rate limiter that allows `rate` requests per second
// with a maximum burst size.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return newRateLimiter(rate, burst, nil)
}

// NewRateLimiterWithTrustedProxies creates a rate limiter that trusts
// X-Forwarded-For when the direct peer is within the given CIDR ranges.
func NewRateLimiterWithTrustedProxies(rate float64, burst int, trustedProxies []*net.IPNet) *RateLimiter {
	return newRateLimiter(rate, burst, trustedProxies)
}

// WithMaxVisitors overrides the maximum number of unique IP addresses tracked
// concurrently and returns the receiver for chaining. A value <= 0 means no cap.
func (rl *RateLimiter) WithMaxVisitors(n int) *RateLimiter {
	rl.mu.Lock()
	rl.maxVisitors = n
	rl.mu.Unlock()
	return rl
}

func newRateLimiter(rate float64, burst int, trustedProxies []*net.IPNet) *RateLimiter {
	cleanup := 5 * time.Minute
	var copied []*net.IPNet
	if len(trustedProxies) > 0 {
		copied = make([]*net.IPNet, len(trustedProxies))
		copy(copied, trustedProxies)
	}
	return &RateLimiter{
		visitors:       make(map[string]*visitor),
		nextCleanup:    time.Now().Add(cleanup),
		rate:           rate,
		burst:          burst,
		cleanup:        cleanup,
		maxVisitors:    DefaultRateLimiterMaxVisitors,
		trustedProxies: copied,
	}
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if !now.Before(rl.nextCleanup) {
		staleBefore := now.Add(-rl.cleanup)
		for k, v := range rl.visitors {
			if v.lastSeen.Before(staleBefore) {
				delete(rl.visitors, k)
			}
		}
		rl.nextCleanup = now.Add(rl.cleanup)
	}

	if rl.visitors == nil {
		rl.visitors = make(map[string]*visitor)
	}
	v, exists := rl.visitors[key]
	if !exists {
		// Block unseen IPs without map growth when the cap is reached.
		// maxVisitors <= 0 means no cap (safe for zero-value RateLimiter{}).
		if rl.maxVisitors > 0 && len(rl.visitors) >= rl.maxVisitors {
			return false
		}
		rl.visitors[key] = &visitor{tokens: float64(rl.burst) - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(v.lastSeen).Seconds()
	v.tokens += elapsed * rl.rate
	if v.tokens > float64(rl.burst) {
		v.tokens = float64(rl.burst)
	}
	v.lastSeen = now

	if v.tokens < 1 {
		return false
	}
	v.tokens--
	return true
}

func (rl *RateLimiter) clientIP(r *http.Request) string {
	if rl.trustedProxies != nil {
		return ipFromRequestTrusted(r, rl.trustedProxies)
	}
	return ipFromRequest(r)
}

// Allow reports whether the request's client IP is within the rate limit.
func (rl *RateLimiter) Allow(r *http.Request) bool {
	return rl.allow(rl.clientIP(r))
}

// Middleware returns Chi-compatible middleware applying rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(r) {
			jsonError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Wrap wraps a HandlerFunc with rate limiting.
func (rl *RateLimiter) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return rl.Middleware(next).ServeHTTP
}

// ParseTrustedProxyCIDRs parses a comma-separated CIDR string.
func ParseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	cidrs := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", p, err)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}

func ipFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ipFromRequestTrusted(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteHost := ipFromRequest(r)
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || !isTrusted(remoteIP, trustedProxies) {
		return remoteHost
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteHost
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if candidate == "" {
			continue
		}
		ip := net.ParseIP(candidate)
		if ip == nil {
			host, _, err := net.SplitHostPort(candidate)
			if err == nil {
				ip = net.ParseIP(host)
				if ip != nil && !isTrusted(ip, trustedProxies) {
					return host
				}
			}
			continue
		}
		if !isTrusted(ip, trustedProxies) {
			return candidate
		}
	}
	return remoteHost
}

func isTrusted(ip net.IP, cidrs []*net.IPNet) bool {
	for _, cidr := range cidrs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}
