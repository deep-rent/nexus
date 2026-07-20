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

// Package app provides a managed lifecycle for long-running applications such
// as servers, workers and daemons, ensuring graceful shutdown on OS signals.
//
// [Run], [RunAll] and [RunStages] are the entry points. They execute your
// application [Component] functions, listen for interrupt signals, and
// propagate cancellation so that every component can clean up before the
// process exits.
//
// # Shutdown
//
// A shutdown is triggered by any of the following:
//
//   - an OS signal, by default [syscall.SIGINT] or [syscall.SIGTERM],
//   - cancellation of the parent context passed to [WithContext],
//   - a [Component] returning a non-nil error or panicking,
//   - all components having returned.
//
// A component that returns nil is considered done, not fatal: the remaining
// components keep running. This makes it safe to mix one-shot work, such as
// schema migrations, with components that run for the lifetime of the process.
//
// Once shutdown begins, component contexts are canceled and the runner waits
// up to the timeout set by [WithTimeout]. Errors from all components are
// collected and returned as a single joined error; errors that wrap
// [context.Canceled] are discarded, since they are the expected result of
// cancellation.
//
// The runner restores the default OS signal disposition as soon as shutdown
// begins, so a second interrupt terminates the process immediately rather than
// waiting for a stuck component.
//
// # Startup order
//
// [RunStages] starts components in ordered stages. All components of a stage
// run concurrently, but a stage is only started once every component of the
// preceding stage has signalled readiness via [Ready] or has returned. On
// shutdown, stages are stopped in reverse order, so dependencies outlive their
// dependents.
//
// # Usage
//
// A typical application starts a background worker alongside a server:
//
//	func main() {
//	  logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
//
//	  worker := func(ctx context.Context) error {
//	    ticker := time.NewTicker(time.Second)
//	    defer ticker.Stop()
//	    for {
//	      select {
//	      case <-ctx.Done():
//	        return nil
//	      case <-ticker.C:
//	        app.Logger(ctx).Info("Working...")
//	      }
//	    }
//	  }
//
//	  srv := &http.Server{Addr: ":8080"}
//	  server := app.Graceful(
//	    func(ctx context.Context) error {
//	      app.Ready(ctx)
//	      err := srv.ListenAndServe()
//	      if errors.Is(err, http.ErrServerClosed) {
//	        return nil
//	      }
//	      return err
//	    },
//	    srv.Shutdown,
//	  )
//
//	  err := app.RunAll(
//	    []app.Component{
//	      app.Named("worker", worker),
//	      app.Named("server", server),
//	    },
//	    app.WithLogger(logger),
//	  )
//	  if err != nil {
//	    logger.Error("Application failed", slog.Any("error", err))
//	    os.Exit(1)
//	  }
//	}
package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// DefaultTimeout is the default duration to wait for components to return
	// after a shutdown has been triggered.
	DefaultTimeout = 10 * time.Second

	// DefaultStartTimeout is the default duration to wait for a [Stage] to
	// signal readiness before the next stage is started.
	DefaultStartTimeout = 30 * time.Second
)

// Stage is a group of [Component] functions that are started concurrently. See
// [RunStages] for how stages are ordered.
type Stage []Component

// config holds the internal settings for the application runner, including
// logging, timeouts, signal handling, and parent context.
type config struct {
	logger  *slog.Logger
	timeout time.Duration
	start   time.Duration
	signals []os.Signal
	ctx     context.Context
}

// Option is a function that configures the application runner [config].
type Option func(*config)

// WithLogger provides a custom [slog.Logger] for the application runner. It is
// also made available to components via [Logger]. If not set, the runner
// defaults to [slog.Default]. A nil value will be ignored.
func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.logger = log
		}
	}
}

// WithTimeout sets the total duration granted to the shutdown process. If the
// components take longer than this to return, the runner gives up waiting and
// returns an error wrapping [ErrShutdownTimeout]. The same duration is
// reported to components by [ShutdownTimeout]. A negative or zero duration
// will be ignored, and [DefaultTimeout] is used instead.
//
// Note that the runner cannot forcibly terminate a component that ignores its
// context. On timeout it returns while those goroutines are still running,
// under the assumption that the caller exits the process shortly after.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithStartTimeout sets the duration to wait for a [Stage] to signal readiness
// before the next stage is started. If the stage does not become ready in
// time, startup is aborted with an error wrapping [ErrStartTimeout]. A
// negative or zero duration will be ignored, and [DefaultStartTimeout] is used
// instead. This setting has no effect unless [RunStages] is used with more
// than one stage.
func WithStartTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.start = d
		}
	}
}

// WithSignals selects the [os.Signal] values that trigger a shutdown,
// replacing the default of [syscall.SIGTERM] and [syscall.SIGINT]. Passing no
// signals disables signal handling entirely, which is useful when the runner
// is embedded in a process that traps signals itself.
func WithSignals(signals ...os.Signal) Option {
	return func(c *config) {
		c.signals = slices.Clone(signals)
	}
}

// WithContext sets a parent [context.Context] for the runner. Cancelling it
// triggers a graceful shutdown. If not set, [context.Background] is used as
// the default parent. A nil value will be ignored.
//
// Because component contexts derive from this parent, cancelling it cancels
// every component at once. Ordered, reverse-stage shutdown as described in
// [RunStages] therefore only applies to shutdowns triggered by a signal or by
// a component.
func WithContext(ctx context.Context) Option {
	return func(c *config) {
		if ctx != nil {
			c.ctx = ctx
		}
	}
}

// Run provides a managed execution environment for a single [Component]. It
// launches the component in a separate goroutine and blocks until it returns,
// an OS signal is caught, or the parent context is canceled. For running
// multiple components concurrently, see [RunAll].
func Run(component Component, opts ...Option) error {
	return RunAll([]Component{component}, opts...)
}

// RunAll provides a managed execution environment for multiple [Component]
// functions running concurrently. It blocks until a shutdown is triggered as
// described in the package documentation, then cancels the components and
// waits for them to return.
//
// The returned error joins the errors of all components that failed. It is nil
// if every component returned nil or an error wrapping [context.Canceled]. Use
// [errors.Is] and [errors.As] to inspect it; in particular, a component that
// panicked yields a [PanicError], and a component wrapped in [Named] yields a
// [ComponentError].
//
// Use [RunStages] if the components must be started in a particular order.
func RunAll(components []Component, opts ...Option) error {
	return RunStages([]Stage{Stage(components)}, opts...)
}

// RunStages provides a managed execution environment for ordered stages of
// [Component] functions. The components of a stage are started concurrently; a
// stage is started only after every component of the preceding stage has
// signalled readiness via [Ready] or has returned. If a stage does not become
// ready within the startup timeout, startup is aborted and the already running
// stages are shut down. See [WithStartTimeout].
//
// On shutdown, stages are canceled in reverse order, and each stage is fully
// drained before the preceding one is canceled. This lets infrastructure
// components such as database pools outlive the components that depend on
// them. The shutdown timeout set by [WithTimeout] applies to the entire
// sequence, not to each stage individually.
//
// Error handling matches [RunAll], which is the single-stage form of this
// function.
func RunStages(stages []Stage, opts ...Option) error {
	cfg := config{
		logger:  slog.Default(),
		timeout: DefaultTimeout,
		start:   DefaultStartTimeout,
		signals: []os.Signal{syscall.SIGTERM, syscall.SIGINT},
		ctx:     context.Background(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	total := 0
	for _, stage := range stages {
		for _, c := range stage {
			if c == nil {
				return ErrNilComponent
			}
			total++
		}
	}
	if total == 0 {
		return ErrNoComponents
	}

	r := &runner{
		cfg:     cfg,
		trigger: make(chan struct{}),
		started: make([]*stage, 0, len(stages)),
	}
	r.remaining.Store(int64(total))
	return r.run(stages)
}

// stage holds the runtime state of a single [Stage].
type stage struct {
	cancel  context.CancelFunc // stops the components of this stage
	running sync.WaitGroup     // components that have not returned yet
	ready   sync.WaitGroup     // components that are not yet ready

	// mu guards errs, which may still be written to by components that
	// outlive the shutdown timeout.
	mu   sync.Mutex
	errs []error
}

// runner executes stages and coordinates their shutdown.
type runner struct {
	cfg      config
	trigger  chan struct{} // closed once shutdown must begin
	shutdown sync.Once     // guards the closing of trigger
	started  []*stage      // stages launched so far, in order

	// remaining counts components that have not returned yet, across all
	// stages, including those that have not been started.
	remaining atomic.Int64
}

// fire triggers the shutdown. It is safe to call concurrently and repeatedly.
func (r *runner) fire() {
	r.shutdown.Do(func() { close(r.trigger) })
}

func (r *runner) run(stages []Stage) error {
	cfg := r.cfg

	// Signals and parent cancellation act as shutdown triggers only. In
	// particular, the signal context is not used as the parent of the
	// component contexts: stopping signal delivery cancels that context, which
	// would defeat the reverse-order shutdown below.
	sigCtx := cfg.ctx
	stopSignals := func() {}
	if len(cfg.signals) > 0 {
		sigCtx, stopSignals = signal.NotifyContext(cfg.ctx, cfg.signals...)
	}
	defer stopSignals()

	go func() {
		select {
		case <-sigCtx.Done():
			r.fire()
		case <-r.trigger:
		}
	}()

	base := context.WithValue(cfg.ctx, loggerKey{}, cfg.logger)
	base = context.WithValue(base, timeoutKey{}, cfg.timeout)

	cfg.logger.Info(
		"Application starting",
		slog.Int("stages", len(stages)),
		slog.Int("components", int(r.remaining.Load())),
	)

	startErr := r.start(base, stages)

	<-r.trigger

	// Determine the cause before stopping signal delivery, which cancels
	// sigCtx as a side effect.
	var reason string
	switch {
	case cfg.ctx.Err() != nil:
		reason = "parent context canceled"
	case sigCtx.Err() != nil:
		reason = "signal received"
	case startErr != nil:
		reason = "startup failed"
	default:
		reason = "component exited"
	}

	// Restore the default signal disposition, so that a second interrupt
	// terminates a process whose components refuse to stop.
	stopSignals()
	cfg.logger.Info("Shutting down", slog.String("reason", reason))

	timedOut := r.stop()
	return r.result(startErr, timedOut)
}

// start launches the stages in order, waiting for each one to become ready
// before starting the next. It returns a non-nil error if startup was aborted
// because a stage did not become ready in time.
func (r *runner) start(base context.Context, stages []Stage) error {
	last := len(stages) - 1
	for i, components := range stages {
		ctx, cancel := context.WithCancel(base)
		s := &stage{cancel: cancel, errs: make([]error, len(components))}
		r.started = append(r.started, s)

		for j, c := range components {
			r.launch(ctx, s, j, c)
		}

		r.cfg.logger.Info(
			"Stage started",
			slog.Int("stage", i),
			slog.Int("components", len(components)),
		)

		// The last stage has no dependents, so nothing waits on it.
		if i == last {
			return nil
		}

		ready := make(chan struct{})
		go func() {
			s.ready.Wait()
			close(ready)
		}()

		timer := time.NewTimer(r.cfg.start)
		select {
		case <-ready:
			timer.Stop()
			r.cfg.logger.Info("Stage ready", slog.Int("stage", i))
		case <-r.trigger:
			timer.Stop()
			return nil
		case <-timer.C:
			r.fire()
			return &stageError{stage: i, timeout: r.cfg.start}
		}
	}
	return nil
}

// launch runs a single component in its own goroutine, recording its result in
// the stage and triggering a shutdown if it fails or if it is the last
// component to return.
func (r *runner) launch(
	ctx context.Context,
	s *stage,
	index int,
	c Component,
) {
	s.running.Add(1)
	s.ready.Add(1)

	go func() {
		defer s.running.Done()

		// Returning implies readiness, so that one-shot components do not hold
		// up the stages that follow.
		signal := once(s.ready.Done)
		defer signal()

		err := invoke(context.WithValue(ctx, readyKey{}, signal), c)

		s.mu.Lock()
		s.errs[index] = err
		s.mu.Unlock()

		if err != nil && !errors.Is(err, context.Canceled) {
			r.report(err)
			r.fire()
		}
		if r.remaining.Add(-1) == 0 {
			r.fire()
		}
	}()
}

// report logs a component failure as it happens, so that the cause of a
// cascading shutdown is visible before the runner returns.
func (r *runner) report(err error) {
	var panicErr *PanicError
	if errors.As(err, &panicErr) {
		r.cfg.logger.Error(
			"Component panicked",
			slog.Any("panic", panicErr.Value),
			slog.String("stack", string(panicErr.Stack)),
		)
		return
	}
	r.cfg.logger.Error("Component failed", slog.Any("error", err))
}

// stop cancels the started stages in reverse order, draining each one before
// moving on. It reports whether the shutdown timeout elapsed.
func (r *runner) stop() bool {
	timer := time.NewTimer(r.cfg.timeout)
	defer timer.Stop()

	for i := len(r.started) - 1; i >= 0; i-- {
		s := r.started[i]
		s.cancel()

		drained := make(chan struct{})
		go func() {
			s.running.Wait()
			close(drained)
		}()

		select {
		case <-drained:
			r.cfg.logger.Info("Stage stopped", slog.Int("stage", i))
		case <-timer.C:
			r.cfg.logger.Error(
				"Shutdown timed out",
				slog.Int("stage", i),
				slog.Duration("timeout", r.cfg.timeout),
			)
			return true
		}
	}
	return false
}

// result joins the errors collected from all components with any startup or
// shutdown failure.
func (r *runner) result(startErr error, timedOut bool) error {
	errs := make([]error, 0, len(r.started)+2)
	if timedOut {
		errs = append(errs, ErrShutdownTimeout)
	}
	if startErr != nil {
		errs = append(errs, startErr)
	}

	for _, s := range r.started {
		s.mu.Lock()
		for _, err := range s.errs {
			// Cancellation is the expected outcome of a shutdown, not a
			// failure worth reporting.
			if err != nil && !errors.Is(err, context.Canceled) {
				errs = append(errs, err)
			}
		}
		s.mu.Unlock()
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}

	r.cfg.logger.Info("Shutdown complete")
	return nil
}

// stageError reports a stage that did not become ready in time.
type stageError struct {
	stage   int
	timeout time.Duration
}

// Error implements the error interface.
func (e *stageError) Error() string {
	return ErrStartTimeout.Error() +
		" after " + e.timeout.String() +
		": stage " + strconv.Itoa(e.stage)
}

// Unwrap allows matching against [ErrStartTimeout].
func (e *stageError) Unwrap() error { return ErrStartTimeout }

var _ error = (*stageError)(nil)
