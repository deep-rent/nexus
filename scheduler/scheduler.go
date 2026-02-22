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

// Package scheduler provides a flexible framework for running recurring tasks
// concurrently.
//
// The core of the package is the Scheduler interface, which manages the
// lifecycle of scheduled jobs. The basic unit of work is a Task, which can be
// adapted into a schedulable Tick. A Tick is a self-repeating job that
// determines its own next run time by returning a duration after each
// execution.
//
// # Usage
//
// Helpers like Every and After are provided to easily convert a simple Task
// into a Tick with common scheduling patterns:
//
//   - Every(d, task): Creates a drift-free Tick that runs at a fixed
//     cadence of duration d, accounting for the task's own execution time.
//   - After(d, task): Creates a drifting Tick that waits for a fixed
//     duration d after the previous run completes.
//
// Example:
//
//	s := scheduler.New(context.Background())
//	defer s.Shutdown()
//
//	task := scheduler.TaskFn(func(context.Context) {
//	  slog.Info("Tick!")
//	})
//
//	tick := scheduler.Every(2*time.Second, task)
//	s.Dispatch(tick)
//
//	// Let the scheduler run for a while.
//	time.Sleep(5 * time.Second)
package scheduler

import (
	"context"
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

// TickFn is an adapter to allow the use of ordinary functions as Ticks.
type TickFn func(ctx context.Context) time.Duration

func (f TickFn) Run(ctx context.Context) time.Duration { return f(ctx) }

// Task represents a unit of work to be executed in a scheduler's execution
// loop. Helpers like After and Every adapt a Task into a Tick.
type Task interface {
	// Run executes the job. It accepts a context for cancellation and
	// timeout control.
	Run(ctx context.Context)
}

// TaskFn is an adapter to allow the use of ordinary functions as Tasks.
type TaskFn func(ctx context.Context)

func (f TaskFn) Run(ctx context.Context) { f(ctx) }

// After creates a drifting Tick that runs after a fixed delay.
// The scheduler waits for the full delay after the task has completed, so
// the effective cadence will vary based on the task's execution time.
func After(d time.Duration, task Task) Tick {
	return TickFn(func(ctx context.Context) time.Duration {
		task.Run(ctx)
		return d
	})
}

// Every creates a drift-free Tick that runs at a fixed interval.
// The wrapper measures the Task's execution time and subtracts it from the
// specified interval, ensuring the task starts at a consistent cadence.
//
// If a task's execution time exceeds the interval, the next run will
// start immediately.
func Every(d time.Duration, task Task) Tick {
	return TickFn(func(ctx context.Context) time.Duration {
		start := time.Now()
		task.Run(ctx)
		elapsed := time.Since(start)
		return max(0, d-elapsed)
	})
}

// Scheduler manages the non-blocking execution of Ticks at their intervals.
type Scheduler interface {
	// Context returns the scheduler's context. This context is cancelled when
	// Shutdown is called. Users can select on this context's Done channel to
	// coordinate with the scheduler's termination.
	Context() context.Context
	// Dispatch executes the given tick in a separate goroutine. The tick will
	// run immediately and then repeat according to the duration it returns
	// until the scheduler is shut down. Multiple ticks can be dispatched
	// concurrently without blocking each other.
	Dispatch(tick Tick)
	// Shutdown gracefully stops the scheduler. It cancels the scheduler's context
	// and waits for all its pending tasks to complete. Shutdown blocks until all
	// dispatched goroutines have finished.
	Shutdown()
}

// New creates a new Scheduler whose lifecycle is tied to the provided
// parent context. Cancelling this context will also cause the scheduler to
// shut down.
func New(ctx context.Context) Scheduler {
	ctx, cancel := context.WithCancel(ctx)
	return &scheduler{
		ctx:    ctx,
		cancel: cancel,
	}
}

type scheduler struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (s *scheduler) Context() context.Context {
	return s.ctx
}

func (s *scheduler) Dispatch(tick Tick) {
	s.wg.Go(func() {
		timer := time.NewTimer(0)
		for {
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				timer.Reset(tick.Run(s.ctx))
			}
		}
	})
}

func (s *scheduler) Shutdown() {
	s.cancel()
	s.wg.Wait()
}

var _ Scheduler = (*scheduler)(nil)

// Once creates a synchronous Scheduler that runs each dispatched Tick exactly
// once. Its Dispatch method is blocking and runs the Tick in the calling
// goroutine.
//
// This implementation is useful for testing or for executing a task with the
// same interface but without true background scheduling.
func Once(ctx context.Context) Scheduler {
	return &once{ctx: ctx}
}

type once struct {
	ctx context.Context
}

func (o *once) Context() context.Context { return o.ctx }
func (o *once) Dispatch(tick Tick)       { tick.Run(o.ctx) }
func (o *once) Shutdown()                {}

var _ Scheduler = (*once)(nil)
