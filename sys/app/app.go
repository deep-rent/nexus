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
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/deep-rent/nexus/sys/log"
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
		logger:  log.New(),
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
		base,
		"Application starting",
		log.Int("stages", len(stages)),
		log.Int("components", int(r.remaining.Load())),
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
	cfg.logger.Info(base, "Shutting down", log.String("reason", reason))

	timedOut := r.stop(base)
	return r.result(base, startErr, timedOut)
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
			ctx,
			"Stage started",
			log.Int("stage", i),
			log.Int("components", len(components)),
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
			r.cfg.logger.Info(base, "Stage ready", log.Int("stage", i))
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
			r.report(ctx, err)
			r.fire()
		}
		if r.remaining.Add(-1) == 0 {
			r.fire()
		}
	}()
}

// report logs a component failure as it happens, so that the cause of a
// cascading shutdown is visible before the runner returns.
func (r *runner) report(ctx context.Context, err error) {
	if panicErr, ok := errors.AsType[*PanicError](err); ok {
		r.cfg.logger.Error(
			ctx,
			"Component panicked",
			log.String("panic", fmt.Sprint(panicErr.Value)),
			log.String("stack", string(panicErr.Stack)),
		)
		return
	}
	r.cfg.logger.Error(ctx, "Component failed", log.Error(err))
}

// stop cancels the started stages in reverse order, draining each one before
// moving on. It reports whether the shutdown timeout elapsed.
func (r *runner) stop(ctx context.Context) bool {
	timer := time.NewTimer(r.cfg.timeout)
	defer timer.Stop()

	for i, s := range slices.Backward(r.started) {

		s.cancel()

		drained := make(chan struct{})
		go func() {
			s.running.Wait()
			close(drained)
		}()

		select {
		case <-drained:
			r.cfg.logger.Info(ctx, "Stage stopped", log.Int("stage", i))
		case <-timer.C:
			r.cfg.logger.Error(
				ctx,
				"Shutdown timed out",
				log.Int("stage", i),
				log.Duration("timeout", r.cfg.timeout),
			)
			return true
		}
	}
	return false
}

// result joins the errors collected from all components with any startup or
// shutdown failure.
func (r *runner) result(
	ctx context.Context,
	startErr error,
	timedOut bool,
) error {
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

	r.cfg.logger.Info(ctx, "Shutdown complete")
	return nil
}

// stageError reports a stage that did not become ready in time.
type stageError struct {
	stage   int
	timeout time.Duration
}

// Error implements the [error] interface.
func (e *stageError) Error() string {
	return ErrStartTimeout.Error() +
		" after " + e.timeout.String() +
		": stage " + strconv.Itoa(e.stage)
}

// Unwrap allows matching against [ErrStartTimeout].
func (e *stageError) Unwrap() error { return ErrStartTimeout }

var _ error = (*stageError)(nil)
