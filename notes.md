# Daily Efficiency Improver — goauth Notes

## Build/Test Commands (validated against CI config; network-blocked so cannot run locally)
- Build: `go build ./...`
- Test: `go test -v ./...`  (requires Go 1.26.1; firewall blocks proxy.golang.org)
- Benchmarks: `go test -bench=. -benchmem ./auth/` (new benchmarks added 2026-05-07)
- Format: `go fmt ./...`
- Hard format: `go tool gofumpt -w -l .`
- Lint: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pin> run ./...`
- All: `make all` (runs lint, fmt, test)
- NOTE: Go 1.26.1 toolchain required; network is firewalled (proxy.golang.org blocked). Tests cannot be run locally.

## Efficiency Notes
- No benchmarks exist in the codebase (confirmed by grep) — CHANGED 2026-05-07: added 4 benchmark functions.
- hotpCode (auth/totp.go) is called 3× per ValidateTOTP on every login. Critical path.
- RateLimiter cleanup: lazy, once per 5-minute window — visitors map now bounded to DefaultRateLimiterMaxVisitors=10_000 (PR #213 MERGED).
- apiKeyLastTouchedAt (auth/middleware.go): process-local map for TouchAPIKeyLastUsed throttling — now bounded to apiKeyTouchCacheMaxSize=10_000 (PR #227 submitted 2026-05-08).
- cachingRoleChecker / cachingAdminChecker: well-designed with FIFO eviction and sweep.
- TOTPUsedCodeCache: uses sync.Map with totpCacheKey struct (no string alloc per call).
- cipher.AEAD (GCM) cached in SecretEncrypter — safe for concurrent use after init.
- base32 encoding precomputed as package-level var in auth/totp.go (totpEncoding).
- jsonError (auth/http.go) and writeError (handler/helpers.go): use structs instead of map[string]string (merged PR #128).
- All handler success responses now use structs instead of map[string]string/map[string]bool (merged PR #137).
- ValidateTOTP now creates HMAC once and reuses via hotpCodeWithMAC + mac.Reset() — merged as PR #162.
- auth/totp.go: totpDigitsStr + totpPeriodStr precomputed vars added (PR #170 MERGED 2026-05-03).
- handler/totp.go: totpHandlerEncoding precomputed var added (PR #170 MERGED 2026-05-03).
- handler/helpers.go validatePassword: errPasswordTooShort/errPasswordTooLong now const (not var+fmt.Sprintf); fmt import removed (PR #211 MERGED 2026-05-07).
- New OAuth2Handler (PR #203): login is unavoidably sequential (external API calls); no hot-path efficiency opportunities found.
- auth/ratelimit.go: DefaultRateLimiterMaxVisitors=10_000 constant + maxVisitors field added (PR #213 MERGED 2026-05-07). New IPs blocked without map growth when at capacity.
- maintenance/maintenance.go: slog.Default() called inline at each log site (PR #218 merged), NOT pre-captured at startup. No efficiency concern.
- Full codebase rescan (2026-05-05): smtp/, maintenance/, auth/, handler/ all re-checked. No new efficiency opportunities. Hot-path optimisations exhausted.
- Benchmarks added (2026-05-07): BenchmarkValidateTOTP, BenchmarkHotpCodeWithMAC (auth/totp_test.go); BenchmarkSecretEncrypterEncrypt, BenchmarkSecretEncrypterDecrypt (auth/crypto_test.go). PR submitted.

## Optimisation Backlog
| Priority | Focus Area | Opportunity | Estimated Impact | Status |
|----------|-----------|-------------|-----------------|--------|
| HIGH | Code-Level | hotpCode: replace math.Pow10(totpDigits) with constant 1_000_000 | Remove float64 op + math import on hot auth path | MERGED PR #39 |
| MEDIUM | Code-Level | SecretEncrypter: cache cipher.Block to avoid AES key expansion per call | Saves ~60-100ns on every Encrypt/Decrypt | MERGED PR #44 |
| MEDIUM | Code-Level | hotpCode: fmt.Sprintf("%0*d",...) -> precomputed totpFormat var | Minor format-parse savings, 3× per TOTP validation | MERGED PR #55 |
| MEDIUM | Code-Level | hotpCode: make([]byte,8) -> var msg [8]byte for stack allocation | One fewer heap alloc per hotpCode call (3x/login) | MERGED (in main) |
| MEDIUM | Code-Level | TOTPUsedCodeCache: string concat key -> totpCacheKey struct to save alloc | Save ~43-byte backing array alloc per WasUsed/MarkUsed | MERGED PR #76 |
| MEDIUM | Code-Level | SecretEncrypter: cache cipher.AEAD (GCM wrapper) | Save ~200-500ns + 1 alloc per Encrypt/Decrypt | MERGED PR #80 |
| MEDIUM | Code-Level | ValidateTOTP: base32.StdEncoding.WithPadding(base32.NoPadding) per call -> package-level var | Save ~290-byte heap alloc per ValidateTOTP call | MERGED PR #82 |
| MEDIUM | Code-Level | jsonError/writeError: map[string]string{"error":msg} -> struct | Save ~264 bytes per error response in middleware+handlers | MERGED PR #128 |
| MEDIUM | Code-Level | All handler success responses: 15x map[string]string/bool -> structs | Save ~264 bytes × 15 response paths | MERGED PR #137 |
| MEDIUM | Code-Level | ValidateTOTP: reuse HMAC via hotpCodeWithMAC + mac.Reset() | Save ~600-700 bytes (2 hmac allocs) per TOTP auth attempt | MERGED PR #162 |
| LOW | Code-Level | handler/totp.go Enroll + auth/totp.go TOTPProvisioningURI: precompute base32 encoding + strconv.Itoa constants | Save 3 allocs (~320 bytes) per TOTP enrollment | MERGED PR #170 |
| LOW | Code-Level | handler/helpers.go validatePassword: var+fmt.Sprintf -> const strings + remove fmt import | Compile-time const literals; remove fmt init overhead | MERGED PR #211 |
| MEDIUM | Code-Level | auth/ratelimit.go: visitors map unbounded between 5-min cleanups | Memory+GC under IP flood; add maxVisitors FIFO cap | MERGED PR #213 |
| LOW | Data | Benchmarks for energy-critical code paths (ValidateTOTP, SecretEncrypter) | Enables future evidence-based optimisation | PR #223 submitted 2026-05-07 |
| MEDIUM | Code-Level | `auth/middleware.go` apiKeyLastTouchedAt: unbounded map when all keys fresh + large fleet | Bounded heap + GC (same pattern as PR #213) | PR #227 submitted 2026-05-08 |

## Work In Progress
- Benchmark PR #223 (branch: efficiency/add-energy-benchmarks-auth): CI all green; awaiting maintainer review
- PR #227 (branch: efficiency/bound-apikey-touch-cache): adds apiKeyTouchCacheMaxSize=10_000; submitted 2026-05-08; awaiting CI

## Completed Work
- PR #39: MERGED 2026-04-20 — replace math.Pow10 with totpModulo=1_000_000 integer constant
- PR #44: MERGED ~2026-04-21 — cache cipher.Block in SecretEncrypter
- PR #55: MERGED 2026-04-22 — precomputed totpFormat package-level var
- [8]byte in hotpCode: MERGED (confirmed in main 2026-04-23, no PR number tracked)
- PR #76: MERGED 2026-04-26 — totpCacheKey struct instead of string concat in sync.Map
- PR #80: MERGED 2026-04-26 — cache cipher.AEAD in SecretEncrypter
- PR #82: MERGED 2026-04-26 — precompute base32 encoding as package-level var (totpEncoding)
- PR #128: MERGED (confirmed 2026-04-27) — replace map[string]string error body with struct (jsonError + writeError)
- PR #137: MERGED 2026-04-28 — replace 15x single-key map[string]string/bool success response literals with typed structs
- PR #162: MERGED 2026-04-29 — reuse HMAC in ValidateTOTP via hotpCodeWithMAC + mac.Reset()
- PR #170: MERGED 2026-05-03 by veverkap — precompute totpDigitsStr, totpPeriodStr, totpHandlerEncoding
- PR #172: MERGED 2026-05-03 by veverkap — password error strings as var+fmt.Sprintf (not full const; follow-up is PR #211)
- PR #211: MERGED 2026-05-07 by veverkap — const password error strings + remove fmt import from handler/helpers.go
- PR #213: MERGED 2026-05-07 by veverkap — bound RateLimiter visitors map to DefaultRateLimiterMaxVisitors=10_000

## Backlog Cursor
- Scanned: auth/, handler/, smtp/, maintenance/ directories (full scan complete as of 2026-05-08)
- Major hot-path optimisations exhausted; remaining items are infrastructure/low-priority
- Last tasks run: Task 2 (found apiKeyLastTouchedAt unbounded map), Task 3 (PR #227), Task 4 (PR #223 CI green), Task 7 (updated issue #212)
- Last run: 2026-05-08

## Monthly Activity Issues
- April 2026: Issue #163 (CLOSED 2026-05-01)
- May 2026: Issue #212 (OPEN — created 2026-05-03, updated 2026-05-08)
