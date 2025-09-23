package scheduler

import (
	"context"
	"sync"
	"time"
)

// Tick represents a unit of work that can be scheduled to run repeatedly.
type Tick interface {
	// Run executes the job and returns the duration to wait before the next
	// execution. It accepts a context for cancellation and timeout control.
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
func Every(d time.Duration, task Task) Tick {
	return TickFn(func(ctx context.Context) time.Duration {
		start := time.Now()
		task.Run(ctx)
		elapsed := time.Since(start)
		return max(0, d-elapsed)
	})
}

// Scheduler manages the non-blocking execution of Ticks at timed intervals.
type Scheduler interface {
	// Context returns the scheduler's parent context, which is cancelled when
	// the scheduler is shut down.
	Context() context.Context
	// Dispatch executes the given tick in a separate goroutine. The tick will
	// run immediately and then repeat according to the duration it returns
	// until the scheduler is shut down. Multiple ticks can be dispatched
	// concurrently without blocking each other.
	Dispatch(tick Tick)
	// Shutdown gracefully stops the scheduler and all its pending ticks.
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

// Once creates a synchronous Scheduler that runs a single Tick and exactly
// once, in a blocking manner. This is useful for testing or scenarios where
// scheduling is not required.
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
