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

// Stopping one tick must leave its siblings running.
func TestDispatch_CancelOneTick(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())
	defer s.Shutdown()

	var stopped, kept atomic.Int64

	ran := make(chan struct{})
	var once sync.Once

	cancel := s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		stopped.Add(1)
		once.Do(func() { close(ran) })
		return time.Millisecond
	}))

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		kept.Add(1)
		return time.Millisecond
	}))

	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("tick did not run")
	}

	cancel()
	time.Sleep(20 * time.Millisecond)

	settled := stopped.Load()
	before := kept.Load()

	time.Sleep(50 * time.Millisecond)

	if got := stopped.Load(); got != settled {
		t.Errorf("canceled tick kept running: got %d; want %d", got, settled)
	}

	if got := kept.Load(); got <= before {
		t.Errorf("sibling tick stopped: got %d; want more than %d", got, before)
	}
}

// The returned function tolerates repeated calls, and the scheduler survives.
func TestDispatch_CancelIsIdempotent(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())
	defer s.Shutdown()

	cancel := s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		return time.Hour
	}))

	cancel()
	cancel()

	if err := s.Context().Err(); err != nil {
		t.Errorf("scheduler context: got %v; want nil", err)
	}
}

// Cancelling a tick must not keep Shutdown from draining the rest.
func TestDispatch_CancelThenShutdown(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())

	cancel := s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		return time.Hour
	}))
	cancel()

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		return time.Hour
	}))

	done := make(chan struct{})
	go func() {
		s.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not complete")
	}
}

// Dispatch after shutdown still yields a usable, harmless cancel function.
func TestDispatch_CancelAfterShutdown(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())
	s.Shutdown()

	cancel := s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		return time.Hour
	}))

	if cancel == nil {
		t.Fatal("got nil; want a cancel function")
	}
	cancel()
}

func TestOnce_Dispatch(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	s := schedule.Once(t.Context())
	cancel := s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		calls.Add(1)
		return time.Hour
	}))

	if cancel == nil {
		t.Fatal("got nil; want a cancel function")
	}
	cancel()
	s.Shutdown()

	if got := calls.Load(); got != 1 {
		t.Errorf("calls: got %d; want 1", got)
	}
}
