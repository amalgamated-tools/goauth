# Daily Efficiency Improver — goauth Notes

## Build/Test Commands (validated against CI config; network-blocked so cannot run locally)
- Build: `go build ./...`
- Test: `go test -v ./...`  (requires Go 1.26.1; firewall blocks proxy.golang.org)
- Benchmarks: `go test -bench=. -benchmem ./auth/` (benchmarks added via PR #223 MERGED)
- Format: `go fmt ./...`
- Hard format: `go tool gofumpt -w -l .`
- Lint: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pin> run ./...`
- All: `make all` (runs lint, fmt, test)
- NOTE: Go 1.26.1 toolchain required; network is firewalled (proxy.golang.org blocked). Tests cannot be run locally.

## Efficiency Notes
- hotpCode (auth/totp.go) is called 3× per ValidateTOTP on every login. Critical path. Fully optimised.
- RateLimiter cleanup: lazy, once per 5-minute window — visitors map now bounded to DefaultRateLimiterMaxVisitors=10_000 (PR #213 MERGED).
- apiKeyLastTouchedAt: bounded with FIFO eviction (PR #227 MERGED, then superseded by PR #236 with cleaner FIFO pattern from rbac.go). Both merged 2026-05-10.
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
- 2026-05-17: No new commits since 2026-05-12; no new efficiency opportunities.
- Full codebase rescan (2026-05-05): smtp/, maintenance/, auth/, handler/ all re-checked. No new efficiency opportunities. Hot-path optimisations exhausted.
- Benchmarks added (PR #223 MERGED 2026-05-10): BenchmarkValidateTOTP, BenchmarkHotpCodeWithMAC (auth/totp_test.go); BenchmarkSecretEncrypterEncrypt, BenchmarkSecretEncrypterDecrypt (auth/crypto_test.go).
- OIDCHandler: idTokenVerifier cached at init (PR #274 open 2026-05-15). Saves 1 alloc per OIDC login.

## Optimisation Backlog
| Priority | Focus Area | Opportunity | Estimated Impact | Status |
|----------|-----------|-------------|-----------------|--------|
| LOW | Code-Level | OIDCHandler: cache oidc.IDTokenVerifier at init time | 1 alloc saved per OIDC login | PR #274 open |

## Work In Progress
- None.

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
- PR #223: MERGED 2026-05-10 by veverkap — add energy benchmarks (BenchmarkValidateTOTP, BenchmarkHotpCodeWithMAC, BenchmarkSecretEncrypterEncrypt, BenchmarkSecretEncrypterDecrypt)
- PR #227: MERGED 2026-05-10 by veverkap — bound apiKeyLastTouchedAt cache to apiKeyTouchCacheMaxSize=10_000; superseded by PR #236 with FIFO eviction

## Backlog Cursor
- Scanned: auth/, handler/, smtp/, maintenance/ directories (full scan complete as of 2026-05-17)
- All hot-path optimisations implemented; PR #274 (LOW-priority OIDC verifier caching) open since 2026-05-15
- Last tasks run: Task 4 (PR #274 CI check), Task 2 (no new commits), Task 7 (updated monthly issue #264)
- Last run: 2026-05-17

## Monthly Activity Issues
- April 2026: Issue #163 (CLOSED 2026-05-01)
- May 2026: Issue #212 (CLOSED 2026-05-11 by veverkap); Issue #264 (OPEN, created 2026-05-12)
