# Daily Efficiency Improver — goauth Notes

## Build/Test Commands (validated against CI config; network-blocked so cannot run locally)
- Build: `go build ./...`
- Test: `go test -v ./...`  (requires Go 1.26.1; firewall blocks proxy.golang.org)
- Format: `go fmt ./...`
- Hard format: `go tool gofumpt -w -l .`
- Lint: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pin> run ./...`
- All: `make all` (runs lint, fmt, test)
- NOTE: Go 1.26.1 toolchain required; network is firewalled (proxy.golang.org blocked). Tests cannot be run locally.

## Efficiency Notes
- No benchmarks exist in the codebase (confirmed by grep).
- hotpCode (auth/totp.go) is called 3× per ValidateTOTP on every login. Critical path.
- RateLimiter cleanup: lazy, once per 5-minute window — efficient.
- cachingRoleChecker / cachingAdminChecker: well-designed with FIFO eviction and sweep.
- TOTPUsedCodeCache: uses sync.Map for entries (concurrent-safe, lazy GC sweep).
- cipher.Block (aes.NewCipher) is safe for concurrent reads after construction (key schedule is read-only).

## Optimisation Backlog
| Priority | Focus Area | Opportunity | Estimated Impact | Status |
|----------|-----------|-------------|-----------------|--------|
| HIGH | Code-Level | hotpCode: replace math.Pow10(totpDigits) with constant 1_000_000 | Remove float64 op + math import on hot auth path | MERGED PR #39 |
| MEDIUM | Code-Level | SecretEncrypter: cache cipher.Block to avoid AES key expansion per call | Saves ~60-100ns on every Encrypt/Decrypt | PR #44 submitted |
| MEDIUM | Code-Level | hotpCode: fmt.Sprintf("%0*d",...) uses runtime width — could use "%06d" (static) | Minor format-parse savings, 3× per TOTP validation | Candidate |
| MEDIUM | Code-Level | TOTPUsedCodeCache uses string concat (userID+"\x00"+code) as key — minor alloc per call | Minor per-call alloc savings | Candidate |
| LOW | Data | No benchmarks for any code paths — measurement infrastructure gap | Enables future evidence-based optimisation |

## Work In Progress
- PR #44 submitted: efficiency/cache-aes-cipher-block — cache cipher.Block in SecretEncrypter

## Completed Work
- PR #39: MERGED 2026-04-20 — replace math.Pow10 with totpModulo=1_000_000 integer constant

## Backlog Cursor
- Scanned: auth/, handler/, smtp/ directories
- Last tasks run: Task 3 (implement), Task 7 (monthly summary update)

## Last Run
- 2026-04-20: PR #39 noted as merged. Created PR #44 (cipher.Block caching). Updated monthly issue #40.
