// Package app provides a reusable framework for the lifecycle management of
// command-line applications. It handles graceful shutdown by listening for
// OS interrupt signals and propagating cancellation through a context.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/signal"
)

type config struct {
	logger  *slog.Logger
	timeout time.Duration
}

// Option is a function that configures the application runner.
type Option func(*config)

func WithLogger(logger *slog.Logger) Option {
	return func(opts *config) {
		if logger != nil {
			opts.logger = logger
		}
	}
}

// WithShutdownTimeout sets a custom timeout for the graceful shutdown process.
// If the application logic takes longer than this duration to return after a
// shutdown signal is received, the runner will exit with an error.
func WithShutdownTimeout(d time.Duration) Option {
	return func(opts *config) {
		if d > 0 {
			opts.timeout = d
		}
	}
}

// Run executes the main application logic and handles its lifecycle.
func Run(main func(ctx context.Context) error, opts ...Option) error {
	cfg := config{
		logger:  slog.Default(),
		timeout: 10 * time.Second,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := signal.Shutdown()
	errCh := make(chan error, 1)
	go func() { errCh <- main(ctx) }()

	cfg.logger.Info("Application started")

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("application error: %w", err)
		}
		cfg.logger.Info("Application stopped")
		return nil

	case sig := <-sigCh:
		cfg.logger.Info(
			"Initiating graceful shutdown",
			slog.String("signal", sig.String()),
		)
		cancel()

		select {
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("error during shutdown: %w", err)
			}
			cfg.logger.Info("Shutdown completed")
			return nil
		case <-time.After(cfg.timeout):
			return fmt.Errorf("shutdown timed out after %v", cfg.timeout)
		}
	}
}
