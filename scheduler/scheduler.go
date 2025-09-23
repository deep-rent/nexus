package scheduler

import (
	"context"
	"time"
)

type Job = func(ctx context.Context) time.Duration

func Fixed(d time.Duration, job func(ctx context.Context)) Job {
	return func(ctx context.Context) time.Duration {
		job(ctx)
		return d
	}
}

type Scheduler interface {
	Dispatch(ctx context.Context, job Job)
}

type scheduler struct{}

func (s *scheduler) Dispatch(ctx context.Context, job Job) {
	d := job(ctx)

	for {
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			d = job(ctx)
		}
	}
}
