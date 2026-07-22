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

// started reports when a tick dispatched on s first runs.
func started(t *testing.T, s schedule.Scheduler) time.Duration {
	t.Helper()

	ran := make(chan time.Time, 1)
	var once sync.Once
	start := time.Now()

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		once.Do(func() { ran <- time.Now() })
		return time.Hour
	}))

	select {
	case at := <-ran:
		return at.Sub(start)
	case <-time.After(2 * time.Second):
		t.Fatal("tick did not run")
		return 0
	}
}

// Without a start delay, a tick runs as soon as it is dispatched.
func TestScheduler_StartsImmediately(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context())
	defer s.Shutdown()

	if d := started(t, s); d > 100*time.Millisecond {
		t.Errorf("first run after %v; want an immediate start", d)
	}
}

func TestScheduler_StartDelay(t *testing.T) {
	t.Parallel()

	delay := 50 * time.Millisecond

	s := schedule.New(t.Context(), schedule.WithStartDelay(delay))
	defer s.Shutdown()

	if d := started(t, s); d < delay {
		t.Errorf("first run after %v; want at least %v", d, delay)
	}
}

// Full jitter spreads the first run over the whole delay window.
func TestScheduler_StartJitter(t *testing.T) {
	t.Parallel()

	delay := 200 * time.Millisecond

	s := schedule.New(t.Context(),
		schedule.WithStartDelay(delay),
		schedule.WithStartJitter(1),
	)
	defer s.Shutdown()

	// Ten ticks scattered over the window are overwhelmingly unlikely to all
	// land at the far end of it.
	var early bool
	for range 10 {
		d := started(t, s)
		if d > delay+time.Second {
			t.Fatalf("first run after %v; want at most %v", d, delay)
		}
		if d < delay {
			early = true
		}
	}

	if !early {
		t.Error("no tick started early; jitter was not applied")
	}
}

// Jitter only shortens, so it cannot delay a tick that has no start delay.
func TestScheduler_JitterWithoutDelay(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context(), schedule.WithStartJitter(1))
	defer s.Shutdown()

	if d := started(t, s); d > 100*time.Millisecond {
		t.Errorf("first run after %v; want an immediate start", d)
	}
}

func TestScheduler_StartOptionsIgnoreInvalidValues(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context(),
		schedule.WithStartDelay(0),
		schedule.WithStartDelay(-time.Hour),
		schedule.WithStartJitter(-1),
		schedule.WithStartJitter(5),
	)
	defer s.Shutdown()

	if d := started(t, s); d > 100*time.Millisecond {
		t.Errorf("first run after %v; want an immediate start", d)
	}
}

// A tick that always asks to be re-run immediately would otherwise spin as
// fast as the scheduler can call it.
func TestScheduler_MinInterval(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	s := schedule.New(t.Context(),
		schedule.WithMinInterval(20*time.Millisecond),
	)

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		calls.Add(1)
		return 0 // Asks to run again immediately.
	}))

	time.Sleep(100 * time.Millisecond)
	s.Shutdown()

	// Roughly five runs fit into the window; allow generous headroom for
	// scheduling, but nothing close to an unthrottled loop.
	if n := calls.Load(); n > 20 {
		t.Errorf("calls: got %d; want the interval to be enforced", n)
	}

	if n := calls.Load(); n == 0 {
		t.Error("calls: got 0; want the tick to run")
	}
}

func TestScheduler_MinIntervalIgnoresInvalidValues(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context(),
		schedule.WithMinInterval(0),
		schedule.WithMinInterval(-time.Hour),
	)
	defer s.Shutdown()

	if d := started(t, s); d > 100*time.Millisecond {
		t.Errorf("first run after %v; want an immediate start", d)
	}
}
