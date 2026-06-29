# Weekly Efficiency Improver — goauth memory

## Last updated
2026-06-29

## Validated Commands
- **Build**: `go build ./...` (requires Go 1.26.1; local env has 1.25.11)
- **Test**: `go test -v ./...` (Makefile: `make test`)
- **Test with sum**: `gotestsum -- -v ./...` (Makefile: `make testsum`)
- **Lint**: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pin> run ./...` (Makefile: `make lint`)
- **Format**: `go fmt ./...` (Makefile: `make fmt`) / `go tool gofumpt -w -l .` (Makefile: `make hardfmt`)
- **Benchmarks (TOTP)**: `go test -bench=BenchmarkValidateTOTP -benchmem ./auth/`
- **Benchmarks (HOTP inner)**: `go test -bench=BenchmarkHotpCodeWithMAC -benchmem ./auth/`
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
- `auth/totp.go`: HMAC-SHA1 is reused across 3 time steps in `ValidateTOTP`. `mac.Sum(nil)` alloc replaced with `[sha1.Size]byte` stack buf in PR (this run). `fmt.Sprintf` per call remains (1 alloc/op).
- Caching: `cachingRoleChecker`, `cachingAdminChecker`, and `shouldTouchAPIKeyLastUsed` all use FIFO bounded caches with sweep-based eviction.

## Optimisation Backlog

| Priority | Focus Area    | Opportunity | Estimated Impact |
|----------|---------------|-------------|------------------|
| DONE     | Code-Level    | RateLimiter: map[string]*visitor → map[string]visitor (PR #582) | HIGH: eliminates 1 heap alloc per unique IP |
| DONE     | Code-Level    | TOTP: mac.Sum(nil) → stack [sha1.Size]byte buf in hotpCodeWithMAC (PR this run, 2026-06-29) | MEDIUM: 2 allocs/op → 1 alloc/op per HOTP call |
| LOW      | Code-Level    | RBAC: rolePermissions as map[Role]map[Permission]struct{} for O(1) lookup | LOW: current n is tiny (≤5), linear is cache-friendly |
| LOW      | Measurement   | Add benchmark for middleware auth flow (JWT validate + session lookup) | LOW: infrastructure value |

## Work In Progress
None — PR submitted for TOTP mac.Sum stack-buf optimization (2026-06-29).

## Completed Work
- 2026-06-22: PR #582 created for `map[string]*visitor` → `map[string]visitor` in `RateLimiter`. Eliminates per-IP heap allocation; reduces GC pressure at scale.
- 2026-06-29: PR created (branch: efficiency/totp-stack-buf-sum) for `mac.Sum(nil)` → `mac.Sum(hBuf[:0])` in `hotpCodeWithMAC`. Eliminates 20-byte heap alloc per HOTP call (×3 per ValidateTOTP).

## Issue Tracker
- Monthly Activity Issue for 2026-06: #583 (open, updated 2026-06-29)

## Backlog Cursor
- Issues scan: not yet started (no efficiency-tagged issues found in first scan)
- Tasks last run (2026-06-29): Task 3 (implement), Task 4 (PR maintenance check), Task 7 (monthly issue)
- PR #582 checks: all passing (CodeQL, Analyze — both success)
