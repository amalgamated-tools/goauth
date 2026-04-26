# Contributing to goauth

Thank you for considering a contribution to goauth! This guide covers everything you need to set up a development environment, run tests and linters, and follow the project's coding conventions.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Running tests](#running-tests)
- [Linting and formatting](#linting-and-formatting)
- [Full pre-PR check](#full-pre-pr-check)
- [Coding conventions](#coding-conventions)
- [Submitting changes](#submitting-changes)

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

### Error handling in stores

Store method implementations must return `auth.ErrNotFound` (or wrap it with `fmt.Errorf("…: %w", auth.ErrNotFound)`) when a record does not exist. Never return a driver-specific error such as `sql.ErrNoRows` directly — the handlers use `errors.Is(err, auth.ErrNotFound)` to produce correct HTTP status codes.

### Logging

Use `log/slog` with structured key–value pairs. Pass the request context through to preserve trace correlation. Do not set or replace the global `slog` handler inside library code.

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
4. Ensure the CI checks (lint, format, tests) pass on your PR.

For significant API changes or new features, open an issue first to discuss the design before investing time in an implementation.
