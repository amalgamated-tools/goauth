# `maintenance` package

The `maintenance` package provides a background cleanup goroutine for purging expired tokens, sessions, and challenges from your database.

## Import path

```go
import "github.com/amalgamated-tools/goauth/maintenance"
```

## Usage

```go
stop := maintenance.StartCleanup(ctx, nil, 10*time.Minute,
    sessionStore.DeleteExpiredSessions,
    magicLinkStore.DeleteExpiredMagicLinks,
    passkeyStore.DeleteExpiredChallenges,
    passwordResetStore.DeleteExpiredPasswordResetTokens,
    linkNonceStore.DeleteExpiredLinkNonces,
)
defer stop() // blocks until the goroutine exits
```

## Behaviour

- Each cleaner runs once immediately when `StartCleanup` is called, then once per `interval`. Each cleaner is called with the context passed to `StartCleanup`.
- Errors returned by a cleaner are logged via `slog` at `ERROR` level with the message `"cleanup task failed"` and the fields `cleaner_name` and `error`. `cleaner_name` is usually the fully-qualified function name, but falls back to a synthetic name such as `cleaner[0]` when the runtime cannot resolve one.
- Panics inside a cleaner are recovered and logged at `ERROR` level with the message `"cleanup task panicked"` and the fields `cleaner_name`, `panic`, and `stack`. Neither errors nor panics stop other cleaners from running.
- Log output uses the `logger` passed to `StartCleanup`. When `logger` is nil, `slog.Default()` is resolved at the time each log entry is written — any call to `slog.SetDefault` made after `StartCleanup` returns is immediately reflected in subsequent log entries.
- `stop()` cancels the goroutine and blocks until it exits — always defer it to avoid goroutine leaks.
- `interval` must be positive; `StartCleanup` panics otherwise.

## Observability

`StartCleanup` emits structured log events via `slog.ErrorContext`, propagating the context passed to `StartCleanup` for trace correlation. Log output goes through the `logger` parameter; when nil, it falls back to `slog.Default()` resolved at the time of each log entry.

| Event | Level | `slog` message | Fields |
|---|---|---|---|
| Cleaner returned an error | `ERROR` | `"cleanup task failed"` | `cleaner_name`, `error` |
| Cleaner panicked | `ERROR` | `"cleanup task panicked"` | `cleaner_name`, `panic`, `stack` |
