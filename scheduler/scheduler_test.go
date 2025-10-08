package scheduler_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdapters(t *testing.T) {
	t.Parallel()

	t.Run("TaskFn", func(t *testing.T) {
		t.Parallel()
		var ran atomic.Bool
		task := scheduler.TaskFn(func(context.Context) {
			ran.Store(true)
		})
		task.Run(t.Context())
		assert.True(t, ran.Load(), "should execute the wrapped function")
	})

	t.Run("TickFn", func(t *testing.T) {
		t.Parallel()
		var ran atomic.Bool
		tick := scheduler.TickFn(func(context.Context) time.Duration {
			ran.Store(true)
			return time.Second
		})
		d := tick.Run(t.Context())
		assert.True(t, ran.Load(), "should execute the wrapped function")
		assert.Equal(t, time.Second, d, "should return the correct duration")
	})
}

func TestAfter(t *testing.T) {
	t.Parallel()
	var ran atomic.Bool
	task := scheduler.TaskFn(func(context.Context) {
		ran.Store(true)
	})

	const delay = 50 * time.Millisecond
	tick := scheduler.After(delay, task)
	actual := tick.Run(t.Context())

	assert.True(t, ran.Load(), "should execute the wrapped function")
	assert.Equal(t, delay, actual, "should return the specified delay")
}

func TestEvery(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		interval     time.Duration
		duration     time.Duration
		expectedWait time.Duration
		tolerance    time.Duration
	}{
		{
			name:         "Task faster than interval",
			interval:     100 * time.Millisecond,
			duration:     20 * time.Millisecond,
			expectedWait: 80 * time.Millisecond,
			tolerance:    5 * time.Millisecond,
		},
		{
			name:         "Task slower than interval",
			interval:     50 * time.Millisecond,
			duration:     60 * time.Millisecond,
			expectedWait: 0,
			tolerance:    5 * time.Millisecond,
		},
		{
			name:         "Task equals interval",
			interval:     50 * time.Millisecond,
			duration:     50 * time.Millisecond,
			expectedWait: 0,
			tolerance:    5 * time.Millisecond,
		},
		{
			name:         "Zero interval",
			interval:     0,
			duration:     10 * time.Millisecond,
			expectedWait: 0,
			tolerance:    5 * time.Millisecond,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var ran atomic.Bool
			task := scheduler.TaskFn(func(context.Context) {
				time.Sleep(tc.duration)
				ran.Store(true)
			})

			tick := scheduler.Every(tc.interval, task)
			wait := tick.Run(t.Context())

			assert.True(t, ran.Load(), "should execute the wrapped function")
			assert.InDelta(t, tc.expectedWait, wait, float64(tc.tolerance),
				"wait duration should be the interval minus the task's execution time",
			)
		})
	}
}

func TestScheduler(t *testing.T) {
	t.Parallel()

	t.Run("New and Context", func(t *testing.T) {
		t.Parallel()
		s := scheduler.New(t.Context())
		require.NotNil(t, s)
		require.NotNil(t, s.Context(), "should have a non-nil context")
	})

	t.Run("Parent context cancellation shuts down scheduler", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		s := scheduler.New(ctx)
		require.NoError(t, s.Context().Err())
		cancel()
		select {
		case <-s.Context().Done():
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Context cancellation did not propagate to scheduler")
		}

		assert.ErrorIs(t, s.Context().Err(), context.Canceled,
			"context should be canceled",
		)
	})

	t.Run("Dispatch and Shutdown", func(t *testing.T) {
		t.Parallel()
		s := scheduler.New(t.Context())

		var count atomic.Int32
		tick := scheduler.Every(
			10*time.Millisecond,
			scheduler.TaskFn(func(context.Context) {
				count.Add(1)
			}),
		)

		s.Dispatch(tick)
		time.Sleep(25 * time.Millisecond)
		s.Shutdown()

		final := count.Load()
		assert.GreaterOrEqual(t, final, int32(2),
			"should have run multiple times before shutdown",
		)

		time.Sleep(20 * time.Millisecond)
		assert.Equal(t, final, count.Load(),
			"should not run after scheduler is shut down",
		)
	})

	t.Run("Shutdown blocks until tasks complete", func(t *testing.T) {
		t.Parallel()
		s := scheduler.New(t.Context())

		var wg sync.WaitGroup
		wg.Add(1)

		started := make(chan struct{})
		stopped := make(chan struct{})
		tick := scheduler.After(time.Hour, scheduler.TaskFn(func(context.Context) {
			close(started)
			<-stopped
		}))

		s.Dispatch(tick)
		<-started

		completed := make(chan struct{})
		go func() {
			s.Shutdown()
			close(completed)
			wg.Done()
		}()

		select {
		case <-completed:
			t.Fatal("Shutdown completed before the task was finished")
		case <-time.After(20 * time.Millisecond):
		}
		close(stopped)
		select {
		case <-completed:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Shutdown did not complete after the task finished")
		}

		wg.Wait()
	})

	t.Run("Dispatch multiple ticks concurrently", func(t *testing.T) {
		t.Parallel()
		s := scheduler.New(t.Context())

		var count1, count2 atomic.Int32

		tick1 := scheduler.Every(
			10*time.Millisecond,
			scheduler.TaskFn(func(context.Context) { count1.Add(1) }),
		)
		tick2 := scheduler.Every(
			15*time.Millisecond,
			scheduler.TaskFn(func(context.Context) { count2.Add(1) }),
		)

		s.Dispatch(tick1)
		s.Dispatch(tick2)

		time.Sleep(35 * time.Millisecond)
		s.Shutdown()

		assert.GreaterOrEqual(t, count1.Load(), int32(2),
			"tick 1 should have run multiple times",
		)
		assert.GreaterOrEqual(t, count2.Load(), int32(1),
			"tick 2 should have run multiple times",
		)
	})
}

func TestOnceScheduler(t *testing.T) {
	t.Parallel()

	t.Run("Context", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(t.Context(), "key", "value")
		s := scheduler.Once(ctx)
		assert.Equal(t, ctx, s.Context(),
			"should return the context it was created with",
		)
	})

	t.Run("Dispatch is synchronous and runs once", func(t *testing.T) {
		t.Parallel()
		s := scheduler.Once(t.Context())

		var count atomic.Int32
		tick := scheduler.TickFn(func(context.Context) time.Duration {
			time.Sleep(10 * time.Millisecond)
			count.Add(1)
			return 0
		})

		s.Dispatch(tick)
		assert.Equal(t, int32(1), count.Load(),
			"should run the tick exactly once and block until completion",
		)

		s.Dispatch(tick)
		assert.Equal(t, int32(2), count.Load(),
			"should run the tick each time",
		)
	})

	t.Run("Shutdown is a no-op", func(t *testing.T) {
		t.Parallel()
		s := scheduler.Once(t.Context())
		done := make(chan struct{})
		go func() {
			s.Shutdown()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(50 * time.Millisecond):
			t.Error("Shutdown took too long to execute")
		}
	})
}
