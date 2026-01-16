package app_test

import (
	"bytes"
	"context"
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
		time.Sleep(20 * time.Millisecond)
		close(done)
		return nil
	}

	signal := syscall.SIGUSR1

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(r, app.WithSignals(signal))
	}()

	time.Sleep(20 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	p.Signal(signal)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not return after shutdown signal")
	}

	select {
	case <-done:
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
		time.Sleep(2 * timeout) // Cleanup is stubbornly slow
		return nil
	}

	signal := syscall.SIGUSR1

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.Run(
			r,
			app.WithSignals(signal),
			app.WithTimeout(timeout),
		)
	}()

	time.Sleep(10 * time.Millisecond)

	p, _ := os.FindProcess(os.Getpid())
	p.Signal(signal)

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shutdown timed out")
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not time out as expected")
	}
}

func TestRun_ParentContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
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
