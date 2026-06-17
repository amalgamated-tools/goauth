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
- apiKeyLastTouchedAt: bounded with FIFO eviction (PR #236 MERGED).
- cachingRoleChecker / cachingAdminChecker: well-designed with FIFO eviction and sweep.
- TOTPUsedCodeCache: uses sync.Map with totpCacheKey struct (no string alloc per call).
- cipher.AEAD (GCM) cached in SecretEncrypter — safe for concurrent use after init.
- base32 encoding precomputed as package-level var in auth/totp.go (totpEncoding).
- All handler success/error responses use structs (merged PRs #128, #137).
- ValidateTOTP creates HMAC once and reuses via hotpCodeWithMAC + mac.Reset() (PR #162).
- totpDigitsStr + totpPeriodStr + totpHandlerEncoding precomputed (PR #170 MERGED).
- OIDCHandler: idTokenVerifier cached at init (PR #274 MERGED).
- 2026-05-28: Scanned recent commits — all docs/CI/refactor, no new efficiency opportunities.
- 2026-06-04: PRs #436-#444 merged — docs/refactor/CI; fetchOAuth2JSON helper added (refactor, not efficiency concern). No new efficiency opportunities.
- 2026-06-05: PRs #450-#459 merged — docs, refactoring (logOrDefault), security fix (OIDC nonce replay via PR #452), Logger field additions. No new efficiency opportunities.
- 2026-06-06: No new commits since 2026-06-04. Scanned new MagicLinkHandler (added 2026-06-04): clean and efficient. No new efficiency opportunities.
- 2026-06-08: No new commits since 2026-06-06. No new efficiency opportunities.
- 2026-06-09: No new commits since 2026-06-08. No new efficiency opportunities.
- 2026-06-10: PR #498 merged (refactor: consolidate duplicate tokenTTL logic into shared defaultDuration helper) — refactoring only, no efficiency opportunities. Monthly issue #449 closed by maintainer on 2026-06-09.
- 2026-06-11: No new commits since 2026-06-10. No new efficiency opportunities.
- 2026-06-12: No new commits since 2026-06-11. No new efficiency opportunities.
- 2026-06-13: No new commits since 2026-06-12. No new efficiency opportunities.
- 2026-06-14: No new commits since 2026-06-13. No new efficiency opportunities.
- 2026-06-15: No new commits since 2026-06-14. No new efficiency opportunities.
- 2026-06-16: No new commits since 2026-06-15. No new efficiency opportunities.
- 2026-06-17: No new commits since 2026-06-16. No new efficiency opportunities.
- Full codebase scan complete: All hot-path optimisations exhausted.
- NOTE: June 2026 monthly issue #426 was closed by maintainer as "not_planned" on 2026-06-03.

## Optimisation Backlog
All identified opportunities have been implemented. No open backlog items.

## Work In Progress
- None.

## Completed Work
- PR #39: MERGED — replace math.Pow10 with totpModulo=1_000_000 integer constant
- PR #44: MERGED — cache cipher.Block in SecretEncrypter
- PR #55: MERGED — precomputed totpFormat package-level var
- PR #76: MERGED — totpCacheKey struct instead of string concat in sync.Map
- PR #80: MERGED — cache cipher.AEAD in SecretEncrypter
- PR #82: MERGED — precompute base32 encoding as package-level var (totpEncoding)
- PR #128: MERGED — replace map[string]string error body with struct
- PR #137: MERGED — replace 15x single-key map success response literals with typed structs
- PR #162: MERGED — reuse HMAC in ValidateTOTP via hotpCodeWithMAC + mac.Reset()
- PR #170: MERGED — precompute totpDigitsStr, totpPeriodStr, totpHandlerEncoding
- PR #211: MERGED — const password error strings + remove fmt import
- PR #213: MERGED — bound RateLimiter visitors map to DefaultRateLimiterMaxVisitors=10_000
- PR #223: MERGED — add energy benchmarks
- PR #227: MERGED — bound apiKeyLastTouchedAt cache to 10,000 entries with FIFO eviction
- PR #274: MERGED — cache oidc.IDTokenVerifier at init

## Backlog Cursor
- Scanned: auth/, handler/, smtp/, maintenance/ directories (full scan complete as of 2026-05-27)
- All hot-path optimisations implemented and merged; backlog fully empty
- Last tasks run: Task 7 (update monthly issue)
- Last run: 2026-06-17 14:22 UTC

## Monthly Activity Issues
- April 2026: Issue #163 (CLOSED)
- May 2026: Issues #212, #264, #332, #365, #386, #407 (all CLOSED)
- June 2026: Issue #426 (CLOSED by maintainer as not_planned 2026-06-03); Issue #449 (CLOSED by maintainer as completed 2026-06-09); Issue #518 (open, created 2026-06-10)
