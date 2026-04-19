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

## Optimisation Backlog
| Priority | Focus Area | Opportunity | Estimated Impact | Status |
|----------|-----------|-------------|-----------------|--------|
| HIGH | Code-Level | hotpCode: replace math.Pow10(totpDigits) with constant 1_000_000 | Remove float64 op + math import on hot auth path | PR submitted |
| MEDIUM | Code-Level | hotpCode: fmt.Sprintf("%0*d",...) uses runtime width — could use "%06d" (static) | Minor format-parse savings, 3× per TOTP validation | Candidate |
| MEDIUM | Code-Level | TOTPUsedCodeCache uses string concat (userID+"\x00"+code) as key — minor alloc per call | Minor per-call alloc savings | Candidate |
| MEDIUM | Network/IO | No HTTP response compression (gzip/br) — no middleware in this lib (consumer responsibility) | N/A — lib doesn't serve HTTP directly |
| LOW | Code-Level | crypto.go: Encrypt/Decrypt create a new AES cipher block per call — could cache cipher.Block | Saves ~500ns per encrypt/decrypt if called frequently | Candidate |
| LOW | Data | No benchmarks for any code paths — measurement infrastructure gap | Enables future evidence-based optimisation |

## Work In Progress
- PR submitted: efficiency/totp-constant-modulo — replace math.Pow10 with totpModulo=1_000_000

## Completed Work
(none yet)

## Backlog Cursor
- Scanned: auth/, handler/, smtp/ directories
- Last task: Task 1 (commands), Task 2 (identify), Task 3 (implement)

## Last Run
- 2026-04-19: First run. Discovered commands, scanned codebase, submitted TOTP constant PR.
