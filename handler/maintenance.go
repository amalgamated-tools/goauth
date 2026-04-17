package handler

import (
	"context"
	"log/slog"
	"time"
)

// StartCleanup runs each of the provided cleaner functions on a repeating
// interval inside a background goroutine. It is intended for database
// maintenance tasks such as deleting expired tokens and sessions that should
// not block request handlers.
//
// The returned stop function cancels the goroutine and blocks until it has
// exited. Callers must invoke stop (e.g. via defer) to avoid leaking the
// goroutine.
//
// Example usage:
//
//	stop := handler.StartCleanup(ctx, 10*time.Minute,
//	    magicLinkStore.DeleteExpiredMagicLinks,
//	    passkeyStore.DeleteExpiredChallenges,
//	    sessionStore.DeleteExpiredSessions,
//	)
//	defer stop()
func StartCleanup(ctx context.Context, interval time.Duration, cleaners ...func(context.Context) error) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, cleaner := range cleaners {
					if err := cleaner(ctx); err != nil {
						slog.ErrorContext(ctx, "cleanup task failed", slog.Any("error", err))
					}
				}
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}
