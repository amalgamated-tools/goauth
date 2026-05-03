# `maintenance` package

The `maintenance` package provides a background cleanup goroutine for purging expired tokens, sessions, and challenges from your database.

## Import path

```go
import "github.com/amalgamated-tools/goauth/maintenance"
```

## Usage

```go
stop := maintenance.StartCleanup(ctx, 10*time.Minute,
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
- Errors returned by a cleaner are logged via `slog` at `ERROR` level with the fields `cleaner_name` and `error`. `cleaner_name` is usually the fully-qualified function name, but falls back to a synthetic name such as `cleaner[0]` when the runtime cannot resolve one.
- Panics inside a cleaner are recovered and logged at `ERROR` level with the fields `cleaner_name`, `panic`, and `stack`. Neither errors nor panics stop other cleaners from running.
- Log output uses the `slog.Logger` that was the process-wide default **at the time `StartCleanup` was called**, not at the time each cleaner runs. Configure your logger before calling `StartCleanup`.
- `stop()` cancels the goroutine and blocks until it exits — always defer it to avoid goroutine leaks.
- `interval` must be positive; `StartCleanup` panics otherwise.
