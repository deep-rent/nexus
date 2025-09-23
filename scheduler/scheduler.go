package scheduler

import (
	"context"
	"sync"
	"time"
)

type Job = func(ctx context.Context) time.Duration

func Every(job Job) Job {
	return func(ctx context.Context) time.Duration {
		start := time.Now()
		delay := job(ctx)
		elapsed := time.Since(start)
		return max(0, delay-elapsed)
	}
}

type Task func(ctx context.Context)

func After(d time.Duration, task Task) Job {
	return func(ctx context.Context) time.Duration {
		task(ctx)
		return d
	}
}

type Scheduler interface {
	Dispatch(job Job)
	Shutdown()
}

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
