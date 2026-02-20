// Package app provides a managed lifecycle for command-line applications,
// ensuring graceful shutdown on OS signals.
//
// The Run function is the main entry point. It wraps your application
// components (Runnables), executing them concurrently. It listens for interrupt
// signals (like SIGINT/SIGTERM) and propagates a cancellation signal via a
// context. This allows your application to perform cleanup tasks before
// exiting.
//
// # Usage
//
// A typical use case involves starting workers or servers that run until
// interrupted. The Run function handles signal trapping, concurrency, and
// timeouts, letting you focus on the business logic.
//
//	func main() {
//	  // 1. Configure a logger (slog).
//	  logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
//
//	  // 2. Define the application components.
//	  // These functions block until ctx is canceled or an error occurs.
//	  worker := func(ctx context.Context) error {
//	    logger.Info("Worker started")
//
//	    // Simulate a task that runs periodically.
//	    ticker := time.NewTicker(1 * time.Second)
//	    defer ticker.Stop()
//
//	    for {
//	      select {
//	      case <-ctx.Done():
//	        // Context canceled (signal received or sibling component failed).
//	        logger.Info("Worker stopping...")
//
//	        // Perform cleanup (e.g., closing DB connections).
//	        time.Sleep(500 * time.Millisecond)
//	        return nil
//
//	      case t := <-ticker.C:
//	        logger.Info("Working...", "time", t.Format(time.TimeOnly))
//	      }
//	    }
//	  }
//
//	  server := func(ctx context.Context) error {
//	    logger.Info("Server started")
//	    <-ctx.Done()
//	    logger.Info("Server stopping...")
//	    return nil
//	  }
//
//	  // 3. Run the application components concurrently.
//	  err := app.RunAll(
//	    []app.Runnable{worker, server},
//	    app.WithLogger(logger),
//	  )
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

	"golang.org/x/sync/errgroup"
)

// DefaultTimeout is the default duration to wait for the application to
// gracefully shut down after receiving a termination signal.
const DefaultTimeout = 10 * time.Second

// Runnable defines a function that can be executed by the application runner.
// It receives a context that is canceled when a shutdown signal is received,
// or if another concurrently running Runnable returns an error.
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
// If the application components take longer than this duration to return after
// a shutdown signal is received, the runner will exit with an error. A negative
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

// Run provides a managed execution environment for a single Runnable.
// It launches the Runnable in a separate goroutine and blocks until it
// completes, an OS interrupt signal is caught, or the parent context is
// canceled. For running multiple components concurrently, see All.
func Run(runnable Runnable, opts ...Option) error {
	return RunAll([]Runnable{runnable}, opts...)
}

// RunAll provides a managed execution environment for multiple Runnables.
// It launches each Runnable in a separate goroutine and blocks until they
// all complete on their own, an OS interrupt signal is caught, the parent
// context (if specified via WithContext) is canceled, or any single Runnable
// returns an error.
//
// Upon receiving a signal or encountering an error in any Runnable, it
// cancels the context passed to all Runnables and waits for the specified
// shutdown timeout. The Runnables are expected to honor the context
// cancellation and perform any necessary cleanup before returning. All returns
// any error from the Runnables themselves, or an error if the shutdown process
// times out.
func RunAll(runnables []Runnable, opts ...Option) error {
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

	// Use errgroup to manage concurrent runnables. The group context will be
	// canceled if the base context is canceled, or if any goroutine returns an
	// error.
	g, gCtx := errgroup.WithContext(ctx)

	cfg.logger.Info("Application started", "components", len(runnables))

	for _, fn := range runnables {
		fn := fn // Capture range variable for the goroutine
		g.Go(func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					stack := string(debug.Stack())
					err = fmt.Errorf("application panic: %v\nstack: %s", r, stack)
				}
			}()
			return fn(gCtx)
		})
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- g.Wait()
	}()

	select {
	case err := <-errCh:
		// The application exited naturally or due to a failure in one component.
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
