package app_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/deep-rent/nexus/app"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_Success(t *testing.T) {
	r := func(context.Context) error { return nil }

	err := app.Run(r)
	require.NoError(t, err)
}

func TestRun_AppError(t *testing.T) {
	r := func(context.Context) error { return assert.AnError }

	err := app.Run(r)
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestRun_Panic(t *testing.T) {
	// This ensures the panic recovery logic works and prevents the test
	// runner from crashing.
	r := func(context.Context) error {
		panic("something went terribly wrong")
	}

	err := app.Run(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "application panic")
	assert.Contains(t, err.Error(), "something went terribly wrong")
	assert.Contains(t, err.Error(), "app_test.go")
}

func TestRun_SignalShutdown(t *testing.T) {
	done := make(chan struct{})
	r := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond) // Simulate cleanup work
		close(done)
		return nil
	}

	// Use SIGUSR1 to avoid killing the test runner if something leaks
	sig := syscall.SIGUSR1
	errCh := make(chan error, 1)

	go func() {
		errCh <- app.Run(r, app.WithSignals(sig))
	}()

	time.Sleep(50 * time.Millisecond) // Wait for the app to start up

	// Send signal to self
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(sig))

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("did not return after shutdown signal")
	}

	select {
	case <-done:
		// Success
	case <-time.After(50 * time.Millisecond):
		t.Fatal("cleanup did not finish in time")
	}
}

func TestRun_ContextCanceledIgnored(t *testing.T) {
	// Many libraries return ctx.Err() when they shut down.
	// We want to ensure this is treated as a clean exit, not an error.
	sig := syscall.SIGUSR1
	r := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(r, app.WithSignals(sig))
	}()

	time.Sleep(50 * time.Millisecond)

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(sig)

	select {
	case err := <-errCh:
		require.NoError(t, err, "context.Canceled should be filtered out")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for shutdown")
	}
}

func TestRun_ShutdownTimeout(t *testing.T) {
	timeout := 20 * time.Millisecond
	r := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(5 * timeout) // Cleanup is stubbornly slow
		return nil
	}

	sig := syscall.SIGUSR1
	errCh := make(chan error, 1)

	go func() {
		errCh <- app.Run(
			r,
			app.WithSignals(sig),
			app.WithTimeout(timeout),
		)
	}()

	time.Sleep(50 * time.Millisecond)

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(sig)

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shutdown timed out")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not time out as expected")
	}
}

func TestRun_ParentContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(r, app.WithContext(ctx))
	}()

	time.Sleep(10 * time.Millisecond) // Let the app start up
	cancel()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("did not return after parent context was canceled")
	}
}

func TestRun_WithLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r := func(context.Context) error { return nil }

	err := app.Run(r, app.WithLogger(logger))
	require.NoError(t, err)

	logs := buf.String()
	assert.Contains(t, logs, "Application started")
	assert.Contains(t, logs, "Application stopped")
}

func TestRunAll_Success(t *testing.T) {
	r1 := func(ctx context.Context) error { return nil }
	r2 := func(ctx context.Context) error { return nil }

	err := app.RunAll([]app.Runnable{r1, r2})
	require.NoError(t, err)
}

func TestRunAll_CascadingError(t *testing.T) {
	errTriggered := errors.New("worker 1 failed")
	var worker2Canceled bool

	r1 := func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		return errTriggered
	}

	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			worker2Canceled = true
		}
		return nil
	}

	err := app.RunAll([]app.Runnable{r1, r2})

	require.Error(t, err)
	assert.ErrorIs(t, err, errTriggered)
	assert.True(
		t,
		worker2Canceled,
		"worker 2 should've been canceled when worker 1 failed",
	)
}

func TestRunAll_CascadingPanic(t *testing.T) {
	var worker2Canceled bool

	r1 := func(ctx context.Context) error {
		time.Sleep(10 * time.Millisecond)
		panic("worker 1 panicked")
	}

	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			worker2Canceled = true
		}
		return nil
	}

	err := app.RunAll([]app.Runnable{r1, r2})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "worker 1 panicked")
	assert.True(
		t,
		worker2Canceled,
		"worker 2 should've been canceled when worker 1 panicked",
	)
}

func TestRunAll_SignalShutdownAll(t *testing.T) {
	sig := syscall.SIGUSR1
	var w1Canceled, w2Canceled bool

	r1 := func(ctx context.Context) error {
		<-ctx.Done()
		w1Canceled = true
		return nil
	}
	r2 := func(ctx context.Context) error {
		<-ctx.Done()
		w2Canceled = true
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunAll([]app.Runnable{r1, r2}, app.WithSignals(sig))
	}()

	time.Sleep(50 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(sig))

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for shutdown")
	}

	assert.True(t, w1Canceled, "worker 1 should've received context cancellation")
	assert.True(t, w2Canceled, "worker 2 should've received context cancellation")
}
