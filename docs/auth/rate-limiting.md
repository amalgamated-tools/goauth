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

## Visitor cap

By default, `RateLimiter` tracks at most `auth.DefaultRateLimiterMaxVisitors` (10,000) unique IP addresses concurrently. When the cap is reached, requests from previously-unseen IPs are denied immediately — without growing the map — to bound memory and GC pressure under IP-flood conditions.

Use `WithMaxVisitors` to override the default at construction time:

```go
// Track up to 50,000 unique IPs (high-traffic deployment).
rl := auth.NewRateLimiter(5, 10).WithMaxVisitors(50_000)

// No cap: any value <= 0 removes the limit (use with caution — unbounded memory growth under flood).
rl = auth.NewRateLimiter(5, 10).WithMaxVisitors(0)
```

`WithMaxVisitors` returns the receiver, so it chains directly after the constructor. It is safe to call at any time, including on a limiter that is already handling requests.

!!! warning "In-memory state"
    `RateLimiter` tracks per-IP token buckets in an in-memory map. In a **multi-instance deployment** (e.g. behind a load balancer), each instance maintains its own independent state — a client can exceed the intended limit by spreading requests across instances. For stricter multi-instance enforcement, supplement with a shared external rate limiter (e.g. Redis).

## Observability

`RateLimiter` emits one structured log event via `log/slog`, propagating the request context for trace correlation:

| Event | Level | `slog` message | Condition |
|---|---|---|---|
| JSON serialisation failure in error response | `ERROR` | `"failed to encode JSON error response"` | `json.Encoder.Encode` fails while writing the `429` error body — the HTTP status is already written at that point |
