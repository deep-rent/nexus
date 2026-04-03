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

package scheduler_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/scheduler"
)

func TestAfter(t *testing.T) {
	t.Parallel()

	var seen atomic.Bool
	task := scheduler.TaskFn(func(context.Context) {
		seen.Store(true)
	})

	const delay = 50 * time.Millisecond
	tick := scheduler.After(delay, task)
	actual := tick.Run(t.Context())

	if !seen.Load() {
		t.Error("After.Run() did not execute the wrapped task")
	}
	if got, want := actual, delay; got != want {
		t.Errorf("After.Run() = %v; want %v", got, want)
	}
}

func TestEvery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		interval     time.Duration
		duration     time.Duration
		expectedWait time.Duration
		tolerance    time.Duration
	}{
		{
			name:         "task faster than interval",
			interval:     100 * time.Millisecond,
			duration:     20 * time.Millisecond,
			expectedWait: 80 * time.Millisecond,
			tolerance:    10 * time.Millisecond,
		},
		{
			name:         "task slower than interval",
			interval:     50 * time.Millisecond,
			duration:     60 * time.Millisecond,
			expectedWait: 0,
			tolerance:    10 * time.Millisecond,
		},
		{
			name:         "task equals interval",
			interval:     50 * time.Millisecond,
			duration:     50 * time.Millisecond,
			expectedWait: 0,
			tolerance:    10 * time.Millisecond,
		},
		{
			name:         "zero interval",
			interval:     0,
			duration:     10 * time.Millisecond,
			expectedWait: 0,
			tolerance:    10 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var seen atomic.Bool
			task := scheduler.TaskFn(func(context.Context) {
				time.Sleep(tt.duration)
				seen.Store(true)
			})

			tick := scheduler.Every(tt.interval, task)
			wait := tick.Run(t.Context())

			if !seen.Load() {
				t.Error("Every.Run() did not execute the wrapped task")
			}

			diff := wait - tt.expectedWait
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.tolerance {
				t.Errorf("Every.Run() wait = %v; want %v (±%v)",
					wait, tt.expectedWait, tt.tolerance)
			}
		})
	}
}

func TestScheduler_New(t *testing.T) {
	t.Parallel()

	s := scheduler.New(t.Context())
	if s == nil {
		t.Fatal("scheduler.New() = nil; want non-nil")
	}
	if got := s.Context(); got == nil {
		t.Error("s.Context() = nil; want non-nil")
	}
}

func TestScheduler_Context_Cancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	s := scheduler.New(ctx)

	if err := s.Context().Err(); err != nil {
		t.Fatalf("s.Context().Err() = %v; want nil before cancellation", err)
	}

	cancel()

	select {
	case <-s.Context().Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("context cancellation did not propagate to scheduler")
	}

	if err := s.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Errorf("s.Context().Err() = %v; want %v", err, context.Canceled)
	}
}

func TestScheduler_Dispatch_Shutdown(t *testing.T) {
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
	if final < 2 {
		t.Errorf("count = %d; want >= 2 before shutdown", final)
	}

	time.Sleep(20 * time.Millisecond)
	if got := count.Load(); got != final {
		t.Errorf("count = %d; want %d (no runs after shutdown)", got, final)
	}
}

func TestScheduler_Shutdown_Blocking(t *testing.T) {
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
		t.Fatal("Shutdown() completed before the task finished")
	case <-time.After(20 * time.Millisecond):
	}

	close(stopped)

	select {
	case <-completed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Shutdown() did not complete after task finished")
	}

	wg.Wait()
}

func TestScheduler_Dispatch_Concurrent(t *testing.T) {
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

	if got := count1.Load(); got < 2 {
		t.Errorf("count1 = %d; want >= 2", got)
	}
	if got := count2.Load(); got < 1 {
		t.Errorf("count2 = %d; want >= 1", got)
	}
}

func TestOnceScheduler_Context(t *testing.T) {
	t.Parallel()

	type contextKey struct{}
	var testKey contextKey

	ctx := context.WithValue(t.Context(), testKey, "value")
	s := scheduler.Once(ctx)

	if got, want := s.Context(), ctx; got != want {
		t.Errorf("s.Context() = %v; want %v", got, want)
	}
}

func TestOnceScheduler_Dispatch_Synchronous(t *testing.T) {
	t.Parallel()

	s := scheduler.Once(t.Context())
	var count atomic.Int32

	tick := scheduler.TickFn(func(context.Context) time.Duration {
		time.Sleep(10 * time.Millisecond)
		count.Add(1)
		return 0
	})

	s.Dispatch(tick)
	if got, want := count.Load(), int32(1); got != want {
		t.Errorf("count = %d; want %d after first dispatch", got, want)
	}

	s.Dispatch(tick)
	if got, want := count.Load(), int32(2); got != want {
		t.Errorf("count = %d; want %d after second dispatch", got, want)
	}
}

func TestOnceScheduler_Shutdown_Noop(t *testing.T) {
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
		t.Error("OnceScheduler.Shutdown() blocked; want no-op")
	}
}
