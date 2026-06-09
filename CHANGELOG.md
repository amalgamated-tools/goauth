# Changelog

## [0.7.0](https://github.com/amalgamated-tools/goauth/compare/v0.6.1...v0.7.0) (2026-06-09)


### Features

* **handler:** add Logger field to MagicLinkHandler ([#457](https://github.com/amalgamated-tools/goauth/issues/457)) ([a3bea4d](https://github.com/amalgamated-tools/goauth/commit/a3bea4dac7ae26df0da90855a90373d1ff993122))


### Bug Fixes

* Deduplicate handler logger fallback via shared `logOrDefault` helper ([#453](https://github.com/amalgamated-tools/goauth/issues/453)) ([d480c16](https://github.com/amalgamated-tools/goauth/commit/d480c163cc2660c07b2587fec76f7ada327b5d94))
* **oidc:** add nonce replay protection to OIDC auth flow ([#452](https://github.com/amalgamated-tools/goauth/issues/452)) ([79deba5](https://github.com/amalgamated-tools/goauth/commit/79deba590e7732d1c03ce0707f1647389aef5943))
* orphaned-token cleanup and configurable TTL for MagicLink + EmailVerification handlers ([#489](https://github.com/amalgamated-tools/goauth/issues/489)) ([830de1b](https://github.com/amalgamated-tools/goauth/commit/830de1bdea51979023ebde0c711a3a58610b58c7))

## [0.6.1](https://github.com/amalgamated-tools/goauth/compare/v0.6.0...v0.6.1) (2026-05-26)


### Bug Fixes

* address 7 grumpy review findings (dead guards, naming, logger parity, display name) ([#374](https://github.com/amalgamated-tools/goauth/issues/374)) ([e0be6a6](https://github.com/amalgamated-tools/goauth/commit/e0be6a6417770768679734edb8259ef927884000))
* standardize token-not-found sentinel and add context logging to jsonError ([#392](https://github.com/amalgamated-tools/goauth/issues/392)) ([6fde449](https://github.com/amalgamated-tools/goauth/commit/6fde4498b1389727b854d00212944c074f0543a4))

## [0.6.0](https://github.com/amalgamated-tools/goauth/compare/v0.5.2...v0.6.0) (2026-05-24)


### Features

* add GitHub Actions workflow for Release Please automation ([#358](https://github.com/amalgamated-tools/goauth/issues/358)) ([86d15cb](https://github.com/amalgamated-tools/goauth/commit/86d15cb7b6b5bb5c1889d3a678cdbb8b2adee9ac))
