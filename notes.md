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
| MEDIUM | Code-Level | SecretEncrypter: cache cipher.Block to avoid AES key expansion per call | Saves ~60-100ns on every Encrypt/Decrypt | MERGED PR #44 |
| MEDIUM | Code-Level | hotpCode: fmt.Sprintf("%0*d",...) -> precomputed totpFormat var | Minor format-parse savings, 3× per TOTP validation | MERGED PR #55 |
| MEDIUM | Code-Level | hotpCode: make([]byte,8) -> var msg [8]byte for stack allocation | One fewer heap alloc per hotpCode call (3x/login) | MERGED (in main) |
| MEDIUM | Code-Level | TOTPUsedCodeCache: string concat key -> totpCacheKey struct to save alloc | Save ~43-byte backing array alloc per WasUsed/MarkUsed | PR SUBMITTED (branch: efficiency/totp-cache-struct-key) |
| LOW | Data | No benchmarks for any code paths — measurement infrastructure gap | Enables future evidence-based optimisation |

## Work In Progress
- PR submitted (branch: efficiency/totp-cache-struct-key): totpCacheKey struct instead of string concat in sync.Map

## Completed Work
- PR #39: MERGED 2026-04-20 — replace math.Pow10 with totpModulo=1_000_000 integer constant
- PR #44: MERGED ~2026-04-21 — cache cipher.Block in SecretEncrypter
- PR #55: MERGED 2026-04-22 — precomputed totpFormat package-level var
- [8]byte in hotpCode: MERGED (confirmed in main 2026-04-23, no PR number tracked)

## Backlog Cursor
- Scanned: auth/, handler/, smtp/, maintenance/ directories (full scan complete)
- Last tasks run: Task 3 (implement), Task 7 (monthly summary update)
- Last run: 2026-04-23

## Last Run
- 2026-04-23: [8]byte optimization confirmed in main. Created PR (branch: efficiency/totp-cache-struct-key) for struct key optimization. Updated monthly issue #40.
