// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
// canceled. For running multiple components concurrently, see RunAll.
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
// cancellation and perform any necessary cleanup before returning. RunAll
// returns any error from the Runnables themselves, or an error if the shutdown
// process times out.
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
