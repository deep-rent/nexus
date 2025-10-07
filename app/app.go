// Package app provides a structured framework for managing the lifecycle of
// command-line applications. It simplifies graceful shutdown by handling OS
// interrupt signals (SIGINT, SIGTERM) and propagating a cancellation
// signal through a context.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// DefaultShutdownTimeout is the default duration to wait for the application to
// gracefully shut down after receiving a termination signal.
const DefaultShutdownTimeout = 10 * time.Second

// Runnable defines a function that can be executed by the application runner.
// It receives a context that is canceled when a shutdown signal is received.
// The function should perform its cleanup and return when the context is done.
type Runnable func(ctx context.Context) error

type config struct {
	logger  *slog.Logger
	timeout time.Duration
}

// Option is a function that configures the application runner.
type Option func(*config)

// WithLogger provides a custom logger for the application runner. If not set,
// the runner defaults to slog.Default(). A nil value will be ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(opts *config) {
		if logger != nil {
			opts.logger = logger
		}
	}
}

// WithShutdownTimeout sets a custom timeout for the graceful shutdown process.
// If the application logic takes longer than this duration to return after a
// shutdown signal is received, the runner will exit with an error. A
// non-positive duration will be ignored, and the DefaultShutdownTimeout is
// used instead.
func WithShutdownTimeout(d time.Duration) Option {
	return func(opts *config) {
		if d > 0 {
			opts.timeout = d
		}
	}
}

// Run provides a managed execution environment for a Runnable.
// It launches the Runnable in a separate goroutine and blocks until it
// either completes on its own or an OS interrupt signal is caught.
//
// Upon receiving a signal, it cancels the context passed to the Runnable
// and waits for the specified shutdown timeout. The Runnable is expected
// to honor the context cancellation and perform any necessary cleanup before
// returning. Run returns any error from the Runnable itself, or an error
// if the shutdown process times out.
func Run(fn Runnable, opts ...Option) error {
	cfg := config{
		logger:  slog.Default(),
		timeout: DefaultShutdownTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 1)
	go func() { errCh <- fn(ctx) }()

	cfg.logger.Info("Application started")

	select {
	// Listen for application errors.
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("encountered an application error: %w", err)
		}
		cfg.logger.Info("Application stopped")
		return nil

		// Listen for gracious termination signals.
	case sig := <-sigCh:
		cfg.logger.Info(
			"Initiating graceful shutdown",
			slog.String("signal", sig.String()),
		)
		cancel()

		select {
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("error occurred during shutdown: %w", err)
			}
			cfg.logger.Info("Shutdown completed")
			return nil
		case <-time.After(cfg.timeout):
			return fmt.Errorf("shutdown timed out after %v", cfg.timeout)
		}
	}
}
