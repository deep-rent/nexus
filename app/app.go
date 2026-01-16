// Package app provides a managed lifecycle for command-line applications,
// ensuring graceful shutdown on OS signals.
//
// The Run function is the main entry point. It wraps your application logic,
// listening for interrupt signals (like SIGINT/SIGTERM) and propagating a
// cancellation signal via a context. This allows your application to perform
// cleanup tasks before exiting.
//
// # Usage
//
// A typical use case involves starting a worker or server that runs until
// interrupted. The Run function handles signal trapping and timeouts, letting
// you focus on the business logic.
//
//	func main() {
//		// 1. Configure a logger (slog).
//		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
//
//		// 2. Define the application logic.
//		// This function blocks until ctx is canceled or an error occurs.
//		runnable := func(ctx context.Context) error {
//			logger.Info("Worker started")
//
//			// Simulate a task that runs periodically.
//			ticker := time.NewTicker(1 * time.Second)
//			defer ticker.Stop()
//
//			for {
//				select {
//				case <-ctx.Done():
//					// Context canceled (signal received).
//					logger.Info("Worker stopping...")
//
//					// Perform cleanup (e.g., closing DB connections).
//					time.Sleep(500 * time.Millisecond)
//					return nil
//
//				case t := <-ticker.C:
//					logger.Info("Working...", "time", t.Format(time.TimeOnly))
//				}
//			}
//		}
//
//		// 3. Run the application.
//		if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
//			logger.Error("Application failed", "error", err)
//			os.Exit(1)
//		}
//	}
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
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
func WithLogger(log *slog.Logger) Option {
	return func(opts *config) {
		if log != nil {
			opts.logger = log
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

	// Create a context that cancels on OS signals.
	ctx, cancel := signal.NotifyContext(cfg.ctx, cfg.signals...)
	defer cancel()

	errCh := make(chan error, 1)
	// Run the application logic in a goroutine with panic recovery.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				errCh <- fmt.Errorf("application panic: %v\nstack: %s", r, stack)
			}
		}()
		errCh <- fn(ctx)
	}()

	cfg.logger.Info("Application started")

	select {
	case err := <-errCh:
		// The application exited naturally (without a signal).
		if err != nil {
			return fmt.Errorf("application exited with error: %w", err)
		}
		cfg.logger.Info("Application stopped")
		return nil

	case <-ctx.Done():
		// A signal was received (or parent context canceled).
		cfg.logger.Info("Shutdown signal received, initiating graceful shutdown")

		timer := time.NewTimer(cfg.timeout)
		defer timer.Stop()

		select {
		case err := <-errCh:
			// If the error encountered is just "context canceled", we consider it a
			// successful shutdown.
			if err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("error during graceful shutdown: %w", err)
			}
			cfg.logger.Info("Shutdown completed successfully")
			return nil
		case <-timer.C:
			return fmt.Errorf("shutdown timed out after %v", cfg.timeout)
		}
	}
}
