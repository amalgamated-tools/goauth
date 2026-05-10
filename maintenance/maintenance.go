package maintenance

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"runtime"
	"runtime/debug"
	"time"
)

// StartCleanup runs each of the provided cleaner functions once immediately,
// then again on every interval, inside a background goroutine. It is intended
// for database maintenance tasks such as deleting expired tokens and sessions
// that should not block request handlers.
//
// StartCleanup panics if interval is <= 0.
//
// The returned stop function cancels the goroutine and blocks until it has
// exited. Callers must invoke stop (e.g. via defer) to avoid leaking the
// goroutine.
//
// Example usage:
//
//	stop := maintenance.StartCleanup(ctx, 10*time.Minute,
//	    magicLinkStore.DeleteExpiredMagicLinks,
//	    passkeyStore.DeleteExpiredChallenges,
//	    sessionStore.DeleteExpiredSessions,
//	)
//	defer stop()
func StartCleanup(ctx context.Context, interval time.Duration, cleaners ...func(context.Context) error) (stop func()) {
	if interval <= 0 {
		panic(fmt.Sprintf("StartCleanup: interval must be positive, got %v", interval))
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	names := make([]string, len(cleaners))
	for i, cleaner := range cleaners {
		if fn := runtime.FuncForPC(reflect.ValueOf(cleaner).Pointer()); fn != nil {
			names[i] = fn.Name()
		} else {
			names[i] = fmt.Sprintf("cleaner[%d]", i)
		}
	}

	runCleaners := func() {
		for i, cleaner := range cleaners {
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.ErrorContext(ctx, "cleanup task panicked",
							slog.String("cleaner_name", names[i]),
							slog.Any("panic", r),
							slog.String("stack", string(debug.Stack())),
						)
					}
				}()
				if err := cleaner(ctx); err != nil {
					slog.ErrorContext(ctx, "cleanup task failed", slog.String("cleaner_name", names[i]), slog.Any("error", err))
				}
			}()
		}
	}

	go func() {
		defer close(done)
		runCleaners()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCleaners()
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}
