# Contributing to goauth

Thank you for considering a contribution to goauth! This guide covers everything you need to set up a development environment, run tests and linters, and follow the project's coding conventions.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Running tests](#running-tests)
  - [Code coverage](#code-coverage)
- [Linting and formatting](#linting-and-formatting)
- [Full pre-PR check](#full-pre-pr-check)
- [Coding conventions](#coding-conventions)
- [Submitting changes](#submitting-changes)
- [Releasing](#releasing)

---

## Prerequisites

| Tool | Version |
|---|---|
| Go | 1.26 or later |
| `golangci-lint` | fetched automatically via `go run` in the Makefile |

No other tooling is required to build and test the library.

## Getting started

```sh
git clone https://github.com/amalgamated-tools/goauth.git
cd goauth
go mod download
```

## Running tests

```sh
make test          # go test -v ./...
```

Alternatively, if you have [`gotestsum`](https://github.com/gotestyourself/gotestsum) installed:

```sh
make testsum       # gotestsum -- -v ./...
```

Tests cover every package (`auth`, `handler`, `smtp`, `maintenance`). Because `handler` tests use in-memory store implementations, **no external services are required** to run the full test suite.

### Code coverage

To generate a local coverage profile and inspect it:

```sh
go test -coverprofile=coverage.out -covermode=atomic ./...
go tool cover -func=coverage.out   # per-function summary
go tool cover -html=coverage.out   # open an annotated HTML report
```

In CI, the `go-test` job automatically converts `coverage.out` to Cobertura XML and uploads it to GitHub Code Quality under the label `code-coverage/go-test`. This gives pull requests a coverage delta and file-level breakdown in the review UI.

The upload step runs only on non-fork PRs (and pushes to `main`). It is configured with `fail-on-error: false`, so a transient upload failure surfaces as a warning but never blocks a merge.

## Linting and formatting

```sh
make lint          # runs golangci-lint across all packages
make fmt           # runs go fmt ./...
make hardfmt       # runs gofumpt (stricter formatting; optional)
```

`make lint` also invokes `make lint-require` internally, which enforces the
[assertion convention](#test-assertion-style) described below.

## Full pre-PR check

Run `make all` before opening a pull request. It executes lint, formatting, and
tests in one command:

```sh
make all
```

CI runs the same checks on every push and pull request targeting `main`.

---

## Coding conventions

### Test assertion style

All test files **must** use [`testify/require`](https://pkg.go.dev/github.com/stretchr/testify/require) for assertions. The `t.Error`, `t.Errorf`, `t.Fatal`, `t.Fatalf`, and bare `assert.*` calls are **forbidden** and will cause `make lint-require` (and CI) to fail.

```go
// ✅ correct
require.NoError(t, err)
require.Equal(t, expected, actual)

// ❌ forbidden
assert.NoError(t, err)
t.Fatal("unexpected error", err)
t.Error("wrong value")
```

The `require` package short-circuits a test immediately on failure, which prevents misleading cascading errors and keeps test output readable.

### Test function naming

Test functions must follow the `TestSubject_scenario` naming convention — a PascalCase subject (the function, type, or behavior under test) separated from a lowerCamelCase scenario description by a single underscore:

```go
// ✅ correct
func TestSecretEncrypter_roundtrip(t *testing.T)     { … }
func TestMiddleware_validJWT(t *testing.T)            { … }
func TestExtractToken_fromHeader(t *testing.T)        { … }

// ❌ incorrect — no scenario suffix, or wrong casing
func TestSecretEncrypter(t *testing.T)                { … }
func Test_secretEncrypter_roundtrip(t *testing.T)    { … }
```

Consistent naming makes it easy to identify which component a test covers and what condition it exercises, both in `go test -v` output and in CI logs.

### Error handling in stores

Store method implementations must return `auth.ErrNotFound` (or wrap it with `fmt.Errorf("…: %w", auth.ErrNotFound)`) when a record does not exist. Never return a driver-specific error such as `sql.ErrNoRows` directly — the handlers use `errors.Is(err, auth.ErrNotFound)` to produce correct HTTP status codes.

### Logging

Use `log/slog` with structured key–value pairs and **always pass the request context using the context-aware slog functions** (e.g., `slog.InfoContext(ctx, "msg", ...)`, `slog.ErrorContext(ctx, "msg", ...)`). This preserves trace correlation. Do not set or replace the global `slog` handler inside library code.

### No direct pushes to `main`

All changes must go through a pull request. The `main` branch is protected.

---

## Submitting changes

1. Fork the repository and create a branch from `main`:
   ```sh
   git checkout -b feat/my-feature
   ```
2. Make your changes, add tests, and run `make all` to verify everything passes.
3. Open a pull request against `main` with a clear description of the problem and solution.
   - **PR title must use [Conventional Commits](https://www.conventionalcommits.org/)** because Release Please reads merged commit messages from PR titles.
   - Format: `<type>(optional-scope): description` (for example, `fix(handler): return 404 for missing linked user`).
   - Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
4. Ensure the CI checks (lint, format, and tests) pass on your PR — these are required for merge. The coverage upload runs automatically on non-fork PRs; failures surface as warnings and never block the merge.

For significant API changes or new features, open an issue first to discuss the design before investing time in an implementation.

---

## Releasing

> Releasing is a maintainer-only operation. Only repository members with write access to `main` can create and push release tags.

goauth uses a two-track release model: automated release management via [Release Please](https://github.com/googleapis/release-please) and a helper script for manual tag creation.

### Automated releases (Release Please)

The `.github/workflows/release-please.yml` workflow runs on every push to `main`. Release Please parses [Conventional Commits](https://www.conventionalcommits.org/) in the commit history and:

1. Opens or updates a "Release PR" that bumps the version in `.release-please-manifest.json` and updates `CHANGELOG.md`.
2. When that PR is merged, creates a GitHub release with auto-generated release notes.

The workflow requires a `RELEASE_PLEASE_TOKEN` repository secret (a PAT with `contents: write`, `pull-requests: write`, and `issues: write` scope) and two configuration files at the repository root:

| File | Purpose |
|---|---|
| `release-please-config.json` | Release Please component configuration |
| `.release-please-manifest.json` | Tracks the current version for each component |

No manual steps are needed for routine releases — merge the Release Please PR to publish.

### Manual tag creation (`script/release`)

For cases where an out-of-band tag is required (hot-fix, pre-release, etc.), use the helper script:

```sh
./script/release v1.2.3
```

The script:

1. Validates that `VERSION` follows the `vX.Y.Z` format.
2. Checks that the tag does not already exist.
3. Ensures the working tree is clean (no uncommitted or untracked files).
4. Creates an annotated tag locally and pushes it to `origin`.

```sh
# Examples
./script/release v1.0.0     # initial stable release
./script/release v1.2.3     # patch release

# The following will be rejected
./script/release 1.0.0      # missing 'v' prefix
./script/release v1.0       # not semver — must be X.Y.Z
```

After the tag is pushed, the GitHub Actions release pipeline picks it up and publishes the GitHub release automatically.
