package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStartCleanup_callsCleaners(t *testing.T) {
	var calls atomic.Int64
	cleaner := func(_ context.Context) error {
		calls.Add(1)
		return nil
	}

	stop := StartCleanup(context.Background(), 10*time.Millisecond, cleaner)
	defer stop()

	require.Eventually(t, func() bool {
		return calls.Load() >= 2
	}, 2*time.Second, 5*time.Millisecond)
}

func TestStartCleanup_stopsOnStop(t *testing.T) {
	var calls atomic.Int64
	cleaner := func(_ context.Context) error {
		calls.Add(1)
		return nil
	}

	stop := StartCleanup(context.Background(), 10*time.Millisecond, cleaner)
	// Let it run at least once.
	require.Eventually(t, func() bool {
		return calls.Load() >= 1
	}, 2*time.Second, 5*time.Millisecond)

	stop()
	snapshot := calls.Load()

	// After stop returns, the goroutine has exited so no further calls can occur.
	require.Equal(t, snapshot, calls.Load())
}

func TestStartCleanup_logsErrorAndContinues(t *testing.T) {
	var calls atomic.Int64
	cleaner := func(_ context.Context) error {
		calls.Add(1)
		return errors.New("db error")
	}

	stop := StartCleanup(context.Background(), 10*time.Millisecond, cleaner)
	defer stop()

	// Even when cleaners return errors, the loop must continue.
	require.Eventually(t, func() bool {
		return calls.Load() >= 2
	}, 2*time.Second, 5*time.Millisecond)
}

func TestStartCleanup_multipleCleaners(t *testing.T) {
	var a, b atomic.Int64
	cleanerA := func(_ context.Context) error { a.Add(1); return nil }
	cleanerB := func(_ context.Context) error { b.Add(1); return nil }

	stop := StartCleanup(context.Background(), 10*time.Millisecond, cleanerA, cleanerB)
	defer stop()

	require.Eventually(t, func() bool {
		return a.Load() >= 1 && b.Load() >= 1
	}, 2*time.Second, 5*time.Millisecond)
}

func TestStartCleanup_parentContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var calls atomic.Int64
	cleaner := func(_ context.Context) error {
		calls.Add(1)
		return nil
	}

	stop := StartCleanup(ctx, 10*time.Millisecond, cleaner)
	defer stop()

	require.Eventually(t, func() bool {
		return calls.Load() >= 1
	}, 2*time.Second, 5*time.Millisecond)

	// Cancel the parent context; stop should still be safe to call.
	cancel()
	stop() // must not block or panic
}

func TestStartCleanup_panicsOnInvalidInterval(t *testing.T) {
	noop := func(context.Context) error { return nil }
	require.Panics(t, func() {
		StartCleanup(context.Background(), 0, noop)
	})
	require.Panics(t, func() {
		StartCleanup(context.Background(), -time.Second, noop)
	})
}

func TestStartCleanup_recoversPanic(t *testing.T) {
	var calls atomic.Int64
	cleaner := func(_ context.Context) error {
		calls.Add(1)
		panic("intentional test panic")
	}

	stop := StartCleanup(context.Background(), 10*time.Millisecond, cleaner)
	defer stop()

	// Panicking cleaners must not crash the process; the loop must continue.
	require.Eventually(t, func() bool {
		return calls.Load() >= 2
	}, 2*time.Second, 5*time.Millisecond)
}

func namedErrorCleaner(_ context.Context) error {
	return errors.New("db error")
}

func TestStartCleanupLogsCleanerNameOnError(t *testing.T) {
	var buf bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))

	stop := StartCleanup(context.Background(), time.Hour, namedErrorCleaner)
	slog.SetDefault(orig) // safe to restore immediately — StartCleanup captured the logger at entry
	stop()

	var record struct {
		CleanerName string `json:"cleaner_name"`
	}
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record))
	require.Contains(t, record.CleanerName, "namedErrorCleaner")
}

func namedPanicCleaner(_ context.Context) error {
	panic("intentional test panic")
}

func TestStartCleanupLogsCleanerNameOnPanic(t *testing.T) {
	var buf bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))

	stop := StartCleanup(context.Background(), time.Hour, namedPanicCleaner)
	slog.SetDefault(orig) // safe to restore immediately — StartCleanup captured the logger at entry
	stop()

	var record struct {
		CleanerName string `json:"cleaner_name"`
	}
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record))
	require.Contains(t, record.CleanerName, "namedPanicCleaner")
}
