# Weekly Efficiency Improver — goauth memory

## Last updated
2026-07-06

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
- `auth/totp.go`: HMAC-SHA1 is reused across 3 time steps in `ValidateTOTP`. Two open PRs improve `hotpCodeWithMAC`: PR #591 (mac.Sum stack buf) and new PR (fmt.Sprintf → manual loop). Combined: 2 allocs/op → 1 alloc/op with lower ns/op.
- Caching: `cachingRoleChecker`, `cachingAdminChecker`, and `shouldTouchAPIKeyLastUsed` all use FIFO bounded caches with sweep-based eviction.

## Optimisation Backlog

| Priority | Focus Area    | Opportunity | Estimated Impact |
|----------|---------------|-------------|------------------|
| DONE     | Code-Level    | RateLimiter: map[string]*visitor → map[string]visitor (PR #582) | HIGH: eliminates 1 heap alloc per unique IP |
| DONE     | Code-Level    | TOTP: mac.Sum(nil) → stack [sha1.Size]byte buf in hotpCodeWithMAC (PR #591) | MEDIUM: 2 allocs/op → 1 alloc/op per HOTP call |
| DONE     | Code-Level    | TOTP: fmt.Sprintf → manual 6-digit formatter in hotpCodeWithMAC (PR 2026-07-06) | MEDIUM: removes fmt overhead ~100-200ns/call × 3 per ValidateTOTP |
| LOW      | Code-Level    | RBAC: rolePermissions as map[Role]map[Permission]struct{} for O(1) lookup | LOW: current n is tiny (≤5), linear is cache-friendly |
| LOW      | Measurement   | Add benchmark for middleware auth flow (JWT validate + session lookup) | LOW: infrastructure value |

## Work In Progress
None — PR submitted for fmt.Sprintf → manual formatter (2026-07-06).

## Completed Work
- 2026-06-22: PR #582 created for `map[string]*visitor` → `map[string]visitor` in `RateLimiter`. Eliminates per-IP heap allocation; reduces GC pressure at scale. All CI passing.
- 2026-06-29: PR #591 created for `mac.Sum(nil)` → `mac.Sum(hBuf[:0])` in `hotpCodeWithMAC`. Eliminates 20-byte heap alloc per HOTP call (×3 per ValidateTOTP). All CI passing.
- 2026-07-06: PR created (branch: efficiency/totp-no-fmt-sprintf) for `fmt.Sprintf(totpFormat, otp)` → manual 6-digit byte loop in `hotpCodeWithMAC`. Removes format-parsing/interface-boxing overhead. Also removes totpFormat package-level var.

## Issue Tracker
- Monthly Activity Issue for 2026-06: #583 (CLOSED 2026-07-06)
- Monthly Activity Issue for 2026-07: created this run (number not yet known)

## Backlog Cursor
- Issues scan: no efficiency-tagged issues found in scans; new scan warranted next run
- Tasks last run (2026-07-06): Task 2 (identify), Task 3 (implement), Task 7 (monthly issue)
- PR #582 checks: all passing (CodeQL, Analyze — both success)
- PR #591 checks: all passing (CodeQL, submit-pypi, Analyze — all success)
