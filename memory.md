# Weekly Efficiency Improver — goauth memory

## Last updated
2026-06-22

## Validated Commands
- **Build**: `go build ./...` (requires Go 1.26.1; local env has 1.25.11)
- **Test**: `go test -v ./...` (Makefile: `make test`)
- **Test with sum**: `gotestsum -- -v ./...` (Makefile: `make testsum`)
- **Lint**: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pin> run ./...` (Makefile: `make lint`)
- **Format**: `go fmt ./...` (Makefile: `make fmt`) / `go tool gofumpt -w -l .` (Makefile: `make hardfmt`)
- **Benchmarks (TOTP)**: `go test -bench=BenchmarkValidateTOTP -benchmem ./auth/`
- **Benchmarks (rate limiter)**: `go test -bench=BenchmarkRateLimiterAllow -benchmem ./auth/`
- **Note**: CI uses Go 1.26.1 (`actions/setup-go`); local env is limited to 1.25.11, so tests/builds must run through CI.

## Repository Overview
- **Package**: `github.com/amalgamated-tools/goauth`
- **Language**: Go 1.26.1
- **Packages**: `auth/` (core: JWT, RBAC, rate limiting, TOTP, crypto), `handler/` (HTTP handlers)
- **Router-agnostic**: Uses standard `net/http`

## Efficiency Notes
- `auth/ratelimit.go`: RateLimiter uses token-bucket per IP. Cleanup is lazy (every 5 min). Max visitors cap at 10,000 (memory bounded).
- `auth/rbac.go`: Role permission lookup is O(roles × perms). Cached by `cachingRoleChecker` (5s TTL). For typical deployments (3 roles × 3 perms), the linear scan is fast.
- `auth/totp.go`: HMAC-SHA1 is reused across 3 time steps in `ValidateTOTP`. `mac.Sum(nil)` allocates per step — potential future improvement: pass stack buffer.
- Caching: `cachingRoleChecker`, `cachingAdminChecker`, and `shouldTouchAPIKeyLastUsed` all use FIFO bounded caches with sweep-based eviction.

## Optimisation Backlog

| Priority | Focus Area    | Opportunity | Estimated Impact |
|----------|---------------|-------------|------------------|
| DONE     | Code-Level    | RateLimiter: map[string]*visitor → map[string]visitor (PR created, see below) | HIGH: eliminates 1 heap alloc per unique IP |
| MEDIUM   | Code-Level    | TOTP: `mac.Sum(nil)` in `hotpCodeWithMAC` allocates 20 bytes/call (×3 per ValidateTOTP); use stack buf | MEDIUM: 3 allocs → 0 for hash (1 fmt.Sprintf remains) |
| LOW      | Code-Level    | RBAC: rolePermissions as `map[Role]map[Permission]struct{}` for O(1) lookup | LOW: current n is tiny (≤5), linear is cache-friendly |
| LOW      | Measurement   | Add benchmark for middleware auth flow (JWT validate + session lookup) | LOW: infrastructure value |

## Work In Progress
None — PR submitted for rate limiter optimization.

## Completed Work
- 2026-06-22: PR created for `map[string]*visitor` → `map[string]visitor` in `RateLimiter`. Eliminates per-IP heap allocation; reduces GC pressure at scale.

## Issue Tracker
- Monthly Activity Issue for 2026-06: To be created this run.

## Backlog Cursor
- Issues scan: not yet started (no efficiency-tagged issues found in first scan)
- Tasks last run (2026-06-22): Task 1 (commands), Task 3 (implement), Task 7 (monthly issue)
