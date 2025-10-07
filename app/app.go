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

// DefaultTimeout is the default duration to wait for the application to
// gracefully shut down after receiving a termination signal.
const DefaultTimeout = 10 * time.Second

// Runnable defines a function that can be executed by the application runner.
// It receives a context that is canceled when a shutdown signal is received.
// The function should perform its cleanup and return when the context is done.
type Runnable func(ctx context.Context) error

type config struct {
	logger  *slog.Logger
	timeout time.Duration
	signals []os.Signal
	ctx     context.Context
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

// WithTimeout sets a custom timeout for the graceful shutdown process.
// If the application logic takes longer than this duration to return after a
// shutdown signal is received, the runner will exit with an error. A negative
// or zero duration will be ignored, and the DefaultTimeout is used instead.
func WithTimeout(d time.Duration) Option {
	return func(opts *config) {
		if d > 0 {
			opts.timeout = d
		}
	}
}

// WithSignals allows customization of which OS signals trigger a shutdown.
// If not used, it defaults to SIGTERM and SIGINT.
func WithSignals(signals ...os.Signal) Option {
	return func(c *config) {
		if len(signals) > 0 {
			c.signals = signals
		}
	}
}

// WithContext sets a parent context for the runner. The runner's main
// context will be a child of this parent. Cancelling the parent context
// triggers a graceful shutdown. If not set, context.Background() is used as
// the default parent. A nil value will be ignored.
func WithContext(ctx context.Context) Option {
	return func(c *config) {
		if ctx != nil {
			c.ctx = ctx
		}
	}
}

// Run provides a managed execution environment for a Runnable.
// It launches the Runnable in a separate goroutine and blocks until it
// either completes on its own, an OS interrupt signal is caught, or the parent
// context (if specified via WithContext) is canceled.
//
// Upon receiving a signal, it cancels the context passed to the Runnable
// and waits for the specified shutdown timeout. The Runnable is expected
// to honor the context cancellation and perform any necessary cleanup before
// returning. Run returns any error from the Runnable itself, or an error
// if the shutdown process times out.
func Run(fn Runnable, opts ...Option) error {
	cfg := config{
		logger:  slog.Default(),
		timeout: DefaultTimeout,
		signals: []os.Signal{syscall.SIGTERM, syscall.SIGINT},
		ctx:     context.Background(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	ctx, cancel := signal.NotifyContext(cfg.ctx, cfg.signals...)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- fn(ctx) }()

	cfg.logger.Info("Application started")

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("encountered an application error: %w", err)
		}
		cfg.logger.Info("Application stopped")
		return nil

	case <-ctx.Done():
		cfg.logger.Info("Shutdown signal received, initiating graceful shutdown")

		timer := time.NewTimer(cfg.timeout)
		defer timer.Stop()

		select {
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("error occurred during shutdown: %w", err)
			}
			cfg.logger.Info("Shutdown completed successfully")
			return nil
		case <-timer.C:
			return fmt.Errorf("shutdown timed out after %v", cfg.timeout)
		}
	}
}
