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

// Package schedule provides a flexible framework for running recurring tasks.
//
// This package manages the lifecycle of concurrent, scheduled jobs. The
// basic unit of work is a [Task], which can be adapted into a schedulable
// [Tick]. A [Tick] is a self-repeating job that determines its own next run
// time by returning a duration after each execution.
//
// # Usage
//
// Helpers like [Every] and [After] are provided to easily convert a simple
// [Task] into a [Tick] with common scheduling patterns:
//
//   - [Every]: Creates a drift-free Tick that runs at a fixed cadence,
//     accounting for the task's own execution time.
//   - [After]: Creates a drifting Tick that waits for a fixed duration after
//     the previous run completes.
//
// Example:
//
//	s := schedule.New(context.Background())
//	defer s.Shutdown()
//
//	task := schedule.TaskFn(func(context.Context) {
//	  slog.Info("Tick!")
//	})
//
//	tick := schedule.Every(2*time.Second, task)
//	s.Dispatch(tick)
//
//	// Let the scheduler run for a while.
//	time.Sleep(5 * time.Second)
package schedule

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// Tick represents a unit of work that can be scheduled to run repeatedly.
type Tick interface {
	// Run executes the job and returns the duration to wait before the next
	// execution. It accepts a context that is cancelled when the scheduler
	// is shut down.
	//
	// If the returned duration is zero or negative, the next run is scheduled
	// immediately.
	Run(ctx context.Context) time.Duration
}

// TickFn is an adapter to allow the use of ordinary functions as [Tick]s.
type TickFn func(ctx context.Context) time.Duration

// Run implements [Tick].
func (f TickFn) Run(ctx context.Context) time.Duration { return f(ctx) }

// Task represents a unit of work to be executed in a scheduler loop.
//
// Helpers like [After] and [Every] adapt a [Task] into a [Tick].
type Task interface {
	// Run executes the job. It accepts a context for cancellation and
	// timeout control.
	Run(ctx context.Context)
}

// TaskFn is an adapter to allow the use of ordinary functions as [Task]s.
type TaskFn func(ctx context.Context)

// Run implements [Task].
func (f TaskFn) Run(ctx context.Context) { f(ctx) }

// After creates a drifting [Tick] that runs after a fixed delay.
//
// The scheduler waits for the full delay after the task has completed, so
// the effective cadence will vary based on the task's execution time.
func After(d time.Duration, task Task) Tick {
	return TickFn(func(ctx context.Context) time.Duration {
		task.Run(ctx)
		return d
	})
}

// Every creates a drift-free [Tick] that runs at a fixed interval.
//
// The wrapper measures the [Task] execution time and subtracts it from the
// specified interval, ensuring the task starts at a consistent cadence. If a
// task's execution time exceeds the interval, the next run starts immediately.
func Every(d time.Duration, task Task) Tick {
	return TickFn(func(ctx context.Context) time.Duration {
		start := time.Now()
		task.Run(ctx)
		elapsed := time.Since(start)
		return max(0, d-elapsed)
	})
}

// Scheduler manages the non-blocking execution of [Tick]s at their intervals.
type Scheduler interface {
	// Context returns the scheduler's context. This context is cancelled when
	// Shutdown is called. Users can select on this context's Done channel to
	// coordinate with the scheduler's termination.
	Context() context.Context
	// Dispatch executes the given tick in a separate goroutine. The tick will
	// run immediately and then repeat according to the duration it returns
	// until the scheduler is shut down. Multiple ticks can be dispatched
	// concurrently without blocking each other. Dispatching after Shutdown
	// has been called does nothing.
	Dispatch(tick Tick)
	// Shutdown gracefully stops the scheduler. It cancels the scheduler's
	// context and waits for all its pending tasks to complete. Shutdown blocks
	// until all dispatched goroutines have finished. Once it has been called,
	// no further tick is started, though a tick already in progress runs to
	// completion. It is safe to call Shutdown more than once.
	Shutdown()
}

// New creates a new [Scheduler] tied to the provided parent context.
//
// Cancelling this context will also cause the scheduler to shut down.
func New(ctx context.Context, opts ...Option) Scheduler {
	cfg := config{
		logger:   slog.Default(),
		recovery: DefaultRecoveryDelay,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	ctx, cancel := context.WithCancel(ctx)
	return &scheduler{
		ctx:      ctx,
		cancel:   cancel,
		logger:   cfg.logger,
		recovery: cfg.recovery,
	}
}

// scheduler is the concrete implementation of the [Scheduler] interface.
type scheduler struct {
	ctx      context.Context    // internal lifecycle context
	cancel   context.CancelFunc // stops all dispatched goroutines
	logger   *slog.Logger       // destination for internal logs
	recovery time.Duration      // delay applied after a tick panicked
	wg       sync.WaitGroup     // tracks active task goroutines

	mu     sync.Mutex // guards closed against a concurrent Dispatch
	closed bool       // whether Shutdown has been called
}

// Context implements [Scheduler].
func (s *scheduler) Context() context.Context {
	return s.ctx
}

// Dispatch implements [Scheduler].
func (s *scheduler) Dispatch(tick Tick) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Starting new work once Shutdown has begun would both outlive the
	// scheduler and add to a WaitGroup that is already being waited on.
	if s.closed {
		return
	}

	s.wg.Go(func() {
		timer := time.NewTimer(0)
		defer timer.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-timer.C:
				// A ready timer and a canceled context are chosen between at
				// random, so the context is checked explicitly before
				// committing to another run.
				if s.ctx.Err() != nil {
					return
				}
				timer.Reset(s.run(tick))
			}
		}
	})
}

// run executes a single iteration of tick, converting a panic into a log
// record. A scheduler shared by unrelated jobs must not let one of them take
// down the process, so a panicking tick is reported and rescheduled after the
// recovery delay rather than being propagated.
func (s *scheduler) run(tick Tick) (d time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error(
				"Tick panicked",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			d = s.recovery
		}
	}()

	return tick.Run(s.ctx)
}

// Shutdown implements [Scheduler].
func (s *scheduler) Shutdown() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()

	// Waited on without the lock, so that a concurrent Dispatch returns
	// promptly instead of blocking until every tick has drained.
	s.wg.Wait()
}

var _ Scheduler = (*scheduler)(nil)

// Once creates a synchronous [Scheduler] that runs each [Tick] exactly once.
//
// Its [Scheduler.Dispatch] method is blocking and runs the [Tick] in the
// calling goroutine. This implementation is useful for testing or executing a
// task without true background scheduling.
//
// Unlike the scheduler returned by [New], it does not recover panics: the tick
// runs on the caller's stack, where the caller is better placed to handle
// them, and a swallowed panic would hide failures in tests.
func Once(ctx context.Context) Scheduler {
	return &once{ctx: ctx}
}

// once is a [Scheduler] implementation for synchronous, single execution.
type once struct {
	// ctx is the context passed to executed ticks.
	ctx context.Context
}

// Context implements [Scheduler].
func (o *once) Context() context.Context { return o.ctx }

// Dispatch implements [Scheduler].
func (o *once) Dispatch(tick Tick) { tick.Run(o.ctx) }

// Shutdown implements [Scheduler].
func (o *once) Shutdown() {}

var _ Scheduler = (*once)(nil)
