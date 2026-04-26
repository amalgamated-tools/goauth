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
)
defer stop() // blocks until the goroutine exits
```

## Behaviour

- Each cleaner runs once immediately when `StartCleanup` is called, then once per `interval`. Each cleaner is called with the context passed to `StartCleanup`.
- Panics inside a cleaner are recovered and logged via `slog`; they do not stop other cleaners.
- `stop()` cancels the goroutine and blocks until it exits — always defer it to avoid goroutine leaks.
- `interval` must be positive; `StartCleanup` panics otherwise.
