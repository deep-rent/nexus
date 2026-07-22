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

package schedule_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/schedule"
)

// The initial timer fires immediately, so it competes with an already
// canceled context in the same select. Picked at random, the scheduler would
// start a full run of work it knows has been cancelled.
//
// Note that a tick can still observe cancellation once it is running: that is
// what its context is for. The guarantee tested here is narrower, namely that
// the scheduler never sets a run going when it already knows better.
func TestScheduler_DoesNotStartOnCanceledContext(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	// Repeated, because a biased coin still lands the right way sometimes.
	for range 50 {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		s := schedule.New(ctx)
		s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
			calls.Add(1)
			return time.Hour
		}))
		s.Shutdown()
	}

	if n := calls.Load(); n != 0 {
		t.Errorf("ticks started on a canceled context: got %d; want 0", n)
	}
}

// Shutdown drains in-flight ticks and leaves nothing running behind it.
func TestScheduler_NothingRunsAfterShutdownReturns(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	s := schedule.New(t.Context())
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		calls.Add(1)
		return 0 // Reschedule immediately, maximizing the overlap.
	}))

	time.Sleep(10 * time.Millisecond)
	s.Shutdown()

	settled := calls.Load()
	time.Sleep(50 * time.Millisecond)

	if got := calls.Load(); got != settled {
		t.Errorf("ticks ran after shutdown returned: got %d; want %d",
			got, settled)
	}
}

func TestScheduler_DispatchAfterShutdown(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())
	s.Shutdown()

	var calls atomic.Int64
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		calls.Add(1)
		return time.Hour
	}))

	time.Sleep(20 * time.Millisecond)

	if n := calls.Load(); n != 0 {
		t.Errorf("calls: got %d; want 0", n)
	}
}

// Dispatch must stay safe when it races a shutdown.
func TestScheduler_DispatchDuringShutdown(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
				return time.Hour
			}))
		}
	})

	s.Shutdown()
	wg.Wait()
}

func TestScheduler_ShutdownIsIdempotent(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		return time.Hour
	}))

	s.Shutdown()
	s.Shutdown()

	if err := s.Context().Err(); err == nil {
		t.Error("context should have been canceled")
	}
}

// Cancelling the parent context stops the scheduler too.
func TestScheduler_ParentCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	s := schedule.New(ctx)
	defer s.Shutdown()

	done := make(chan struct{})
	var once sync.Once
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		once.Do(func() { close(done) })
		return time.Hour
	}))

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tick did not run")
	}

	cancel()

	select {
	case <-s.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop with its parent")
	}
}
