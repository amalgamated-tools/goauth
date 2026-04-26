# Rate Limiting

Per-IP token-bucket limiter compatible with `net/http` middleware and `http.HandlerFunc` wrapping.

## Basic limiter

```go
// Simple limiter: 5 requests/second, burst of 10.
rl := auth.NewRateLimiter(5, 10)
r.Use(rl.Middleware)
```

## Behind a reverse proxy

```go
// Trust X-Forwarded-For from known CIDRs.
cidrs, err := auth.ParseTrustedProxyCIDRs("10.0.0.0/8,172.16.0.0/12")
rl := auth.NewRateLimiterWithTrustedProxies(5, 10, cidrs)
r.Use(rl.Middleware)
```

!!! warning "Trusted proxies"
    If your application runs behind a load balancer, use `NewRateLimiterWithTrustedProxies` and restrict the trusted CIDR list to your actual proxy addresses. Trusting arbitrary `X-Forwarded-For` headers allows clients to spoof their IP and bypass rate limiting.

## Single-handler wrapping

```go
// Wrap a single handler instead of a full middleware chain.
http.HandleFunc("/login", rl.Wrap(myHandler))
```

## Programmatic check

```go
// Returns bool, does not write an HTTP response.
if !rl.Allow(r) {
    http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
    return
}
```

Stale visitor entries are swept lazily every 5 minutes.
