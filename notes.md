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
- TOTPUsedCodeCache: uses sync.Map with totpCacheKey struct (no string alloc per call).
- cipher.AEAD (GCM) cached in SecretEncrypter — safe for concurrent use after init.
- base32 encoding precomputed as package-level var in auth/totp.go (totpEncoding).
- jsonError (auth/http.go) and writeError (handler/helpers.go): use structs instead of map[string]string (merged PR #128).
- All handler success responses now use structs instead of map[string]string/map[string]bool (merged PR #137).
- ValidateTOTP now creates HMAC once and reuses via hotpCodeWithMAC + mac.Reset() — merged as PR #162.
- auth/totp.go: totpDigitsStr + totpPeriodStr precomputed vars added (PR #170 submitted).
- handler/totp.go: totpHandlerEncoding precomputed var added (PR #170 submitted).
- handler/helpers.go validatePassword: error strings now const (not var); fmt import removed (PR #172 fixed 2026-05-02).

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
| LOW | Code-Level | handler/totp.go Enroll + auth/totp.go TOTPProvisioningURI: precompute base32 encoding + strconv.Itoa constants | Save 3 allocs (~320 bytes) per TOTP enrollment | PR #170 open |
| LOW | Code-Level | handler/helpers.go validatePassword: fmt.Sprintf -> const strings | Save 1 alloc (~40 bytes) per failed password validation; removes fmt import | PR #172 open (fixed to use const 2026-05-02) |
| LOW | Data | No benchmarks for any code paths — measurement infrastructure gap | Enables future evidence-based optimisation |

## Work In Progress
- PR #170 (branch: efficiency/precompute-totp-enrollment-exprs-6ee5a7a64d7afc46): precompute totpDigitsStr, totpPeriodStr in auth/totp.go + totpHandlerEncoding in handler/totp.go; CI green; awaiting maintainer review
- PR #172 (branch: efficiency/precompute-password-error-strings-746f7beb9208abb3): fixed to use const strings + removed fmt import (commit 2026-05-02); awaiting CI re-run + maintainer review

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

## Backlog Cursor
- Scanned: auth/, handler/, smtp/, maintenance/ directories (full scan complete as of 2026-05-01)
- Major hot-path optimisations exhausted; remaining items are low-priority/rare-path
- Last tasks run: Task 4 (fixed PR #172 to use const + removed fmt; PR #170 unchanged/CI green), Task 7 (updated May issue)
- Last run: 2026-05-02

## Monthly Activity Issues
- April 2026: Issue #163 (CLOSED 2026-05-01)
- May 2026: Issue #174 (open)

## Last Run
- 2026-05-02: Task 4 — fixed PR #172: converted errPasswordTooShort/errPasswordTooLong from var (fmt.Sprintf) to const strings and removed fmt import, addressing Greptile review feedback. PR #170 CI green, no changes needed. Task 7 — updated May 2026 monthly activity issue #174.
