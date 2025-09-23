package scheduler

import (
	"context"
	"sync"
	"time"
)

// Job defines a function that returns the duration to wait before its next run.
// It accepts a context for cancellation and timeout control.
type Job = func(ctx context.Context) time.Duration

// Task represents a unit of work to be executed in a scheduler's execution
// loop. Helpers like After and Every adapt a Task into a Job.
type Task func(ctx context.Context)

// After creates a drifting Job that runs after a fixed delay.
// The scheduler waits for the full delay after the task has completed, so
// the effective cadence will vary based on the task's execution time.
func After(d time.Duration, task Task) Job {
	return func(ctx context.Context) time.Duration {
		task(ctx)
		return d
	}
}

// Every creates a drift-free Job that runs at a fixed interval.
// The wrapper measures the Task's execution time and subtracts it from the
// specified interval, ensuring the task starts at a consistent cadence.
func Every(d time.Duration, task Task) Job {
	return func(ctx context.Context) time.Duration {
		start := time.Now()
		task(ctx)
		elapsed := time.Since(start)
		return max(0, d-elapsed)
	}
}

// Scheduler manages the non-blocking execution of jobs at timed intervals.
type Scheduler interface {
	// Dispatch executes the given job in a separate goroutine. The job will
	// run immediately and then repeat according to the duration it returns
	// until the scheduler is shut down. Multiple jobs can be dispatched
	// concurrently without blocking each other.
	Dispatch(job Job)
	// Shutdown gracefully stops the scheduler and all its pending jobs.
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

func (s *scheduler) Dispatch(job Job) {
	s.wg.Go(func() {
		timer := time.NewTimer(0)
		for {
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				timer.Reset(job(s.ctx))
			}
		}
	})
}

func (s *scheduler) Shutdown() {
	s.cancel()
	s.wg.Wait()
}

var _ Scheduler = (*scheduler)(nil)

// Once creates a synchronous Scheduler that runs a single job and exactly once,
// in a blocking manner. This is useful for testing or scenarios where
// scheduling is not required.
func Once(ctx context.Context) Scheduler {
	return &once{ctx: ctx}
}

type once struct {
	ctx context.Context
}

func (o *once) Dispatch(job Job) { job(o.ctx) }
func (o *once) Shutdown()        {}

var _ Scheduler = (*once)(nil)
