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

package backoff_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
)

// unit keeps the test durations short while remaining readable.
const unit = time.Millisecond

// mockRand returns a fixed value in place of a random one.
type mockRand struct{ val float64 }

func (m *mockRand) Float64() float64 { return m.val }

var _ backoff.Rand = (*mockRand)(nil)

// delays collects the delays of the first n attempts.
func delays(s backoff.Strategy, n int) []time.Duration {
	d := make([]time.Duration, n)
	for i := range d {
		d[i] = s.Delay(i + 1)
	}
	return d
}

// equal reports whether two duration slices hold the same values.
func equal(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConstant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		delay time.Duration
		want  time.Duration
	}{
		{"positive", 100 * unit, 100 * unit},
		{"zero", 0, 0},
		{"negative", -100 * unit, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := backoff.Constant(tt.delay)

			for _, n := range []int{1, 2, 100} {
				if got := s.Delay(n); got != tt.want {
					t.Errorf("delay(%d): got %v; want %v", n, got, tt.want)
				}
			}

			if got := s.MinDelay(); got != tt.want {
				t.Errorf("min delay: got %v; want %v", got, tt.want)
			}

			if got := s.MaxDelay(); got != tt.want {
				t.Errorf("max delay: got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestLinear(t *testing.T) {
	t.Parallel()

	s := backoff.Linear(100*unit, 350*unit)

	want := []time.Duration{
		100 * unit,
		200 * unit,
		300 * unit,
		350 * unit, // Capped.
		350 * unit,
	}

	if got := delays(s, len(want)); !equal(got, want) {
		t.Errorf("delays: got %v; want %v", got, want)
	}
}

// The first retry must wait for exactly the configured minimum delay, not for
// a delay already multiplied by the growth factor.
func TestExponential_FirstDelayIsMinDelay(t *testing.T) {
	t.Parallel()

	s := backoff.Exponential(100*unit, 10000*unit, 2)

	want := []time.Duration{
		100 * unit,
		200 * unit,
		400 * unit,
		800 * unit,
	}

	if got := delays(s, len(want)); !equal(got, want) {
		t.Errorf("delays: got %v; want %v", got, want)
	}
}

// Once the exponential term exceeds what a duration can represent, the delay
// must saturate at the maximum instead of wrapping around.
func TestExponential_SaturatesOnOverflow(t *testing.T) {
	t.Parallel()

	maxDelay := time.Hour
	s := backoff.Exponential(time.Second, maxDelay, 2)

	for _, n := range []int{62, 63, 64, 100, 1000, math.MaxInt32} {
		if got := s.Delay(n); got != maxDelay {
			t.Errorf("delay(%d): got %v; want %v", n, got, maxDelay)
		}
	}
}

func TestLinear_SaturatesOnOverflow(t *testing.T) {
	t.Parallel()

	maxDelay := time.Hour
	s := backoff.Linear(time.Second, maxDelay)

	for _, n := range []int{3601, math.MaxInt32, math.MaxInt64} {
		if got := s.Delay(n); got != maxDelay {
			t.Errorf("delay(%d): got %v; want %v", n, got, maxDelay)
		}
	}
}

// Attempt numbers below one are meaningless and must not produce a delay
// shorter than the minimum.
func TestStrategy_ClampsAttemptNumber(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    backoff.Strategy
	}{
		{"linear", backoff.Linear(100*unit, 1000*unit)},
		{"exponential", backoff.Exponential(100*unit, 1000*unit, 2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want := tt.s.Delay(1)
			for _, n := range []int{0, -1, math.MinInt} {
				if got := tt.s.Delay(n); got != want {
					t.Errorf("delay(%d): got %v; want %v", n, got, want)
				}
			}
		})
	}
}

func TestExponential_DegradesToLinear(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		factor float64
	}{
		{"factor of one", 1},
		{"factor below one", 0.5},
		{"negative factor", -2},
		{"not a number", math.NaN()},
	}

	want := delays(backoff.Linear(100*unit, 1000*unit), 5)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := backoff.Exponential(100*unit, 1000*unit, tt.factor)
			if got := delays(s, len(want)); !equal(got, want) {
				t.Errorf("delays: got %v; want %v", got, want)
			}
		})
	}
}

func TestExponential_DegradesToConstant(t *testing.T) {
	t.Parallel()

	s := backoff.Exponential(500*unit, 400*unit, 2)

	for _, n := range []int{1, 2, 10} {
		if got, want := s.Delay(n), 400*unit; got != want {
			t.Errorf("delay(%d): got %v; want %v", n, got, want)
		}
	}
}

func TestNew_Defaults(t *testing.T) {
	t.Parallel()

	s := backoff.New(backoff.WithJitterAmount(0))

	if got := s.Delay(1); got != backoff.DefaultMinDelay {
		t.Errorf("first delay: got %v; want %v", got, backoff.DefaultMinDelay)
	}

	if got := s.MaxDelay(); got != backoff.DefaultMaxDelay {
		t.Errorf("max delay: got %v; want %v", got, backoff.DefaultMaxDelay)
	}

	want := time.Duration(
		float64(backoff.DefaultMinDelay) * backoff.DefaultGrowthFactor,
	)
	if got := s.Delay(2); got != want {
		t.Errorf("second delay: got %v; want %v", got, want)
	}
}

func TestNew_NegativeDurations(t *testing.T) {
	t.Parallel()

	s := backoff.New(
		backoff.WithMinDelay(-time.Second),
		backoff.WithMaxDelay(-time.Minute),
	)

	if got := s.Delay(1); got != 0 {
		t.Errorf("delay: got %v; want 0", got)
	}
}

// Jitter must apply to every strategy shape, not just the exponential one.
func TestNew_JitterAppliesToEveryStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []backoff.Option
		// base is the delay of the first attempt before jitter.
		base time.Duration
	}{
		{
			name: "exponential",
			opts: []backoff.Option{backoff.WithGrowthFactor(2)},
			base: 100 * unit,
		},
		{
			name: "linear",
			opts: []backoff.Option{backoff.WithGrowthFactor(1)},
			base: 100 * unit,
		},
		{
			name: "constant",
			opts: []backoff.Option{backoff.WithMaxDelay(100 * unit)},
			base: 100 * unit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]backoff.Option{
				backoff.WithMinDelay(100 * unit),
				backoff.WithMaxDelay(1000 * unit),
				backoff.WithJitterAmount(0.5),
				backoff.WithRand(&mockRand{val: 1}),
			}, tt.opts...)

			// With a random factor of 1 and 50% jitter, the delay is halved.
			want := tt.base / 2
			if got := backoff.New(opts...).Delay(1); got != want {
				t.Errorf("delay: got %v; want %v", got, want)
			}
		})
	}
}

func TestJitter(t *testing.T) {
	t.Parallel()

	base := backoff.Constant(100 * unit)

	tests := []struct {
		name   string
		amount float64
		rand   backoff.Rand
		want   time.Duration
	}{
		{"no jitter", 0, &mockRand{val: 1}, 100 * unit},
		{"negative amount", -1, &mockRand{val: 1}, 100 * unit},
		{"half, no randomness", 0.5, &mockRand{val: 0}, 100 * unit},
		{"half, full randomness", 0.5, &mockRand{val: 1}, 50 * unit},
		{"full, full randomness", 1, &mockRand{val: 1}, 0},
		{"amount above one", 2, &mockRand{val: 1}, 0},
		{"default source", 0.5, nil, 0}, // Checked separately below.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := backoff.Jitter(base, tt.amount, tt.rand)

			got := s.Delay(1)
			if tt.rand == nil {
				// The default source is random, so only the range is checked.
				if got < 50*unit || got > 100*unit {
					t.Errorf("delay: got %v; want within [50, 100]", got)
				}
				return
			}

			if got != tt.want {
				t.Errorf("delay: got %v; want %v", got, tt.want)
			}
		})
	}
}

// Jitter shortens delays, so it lowers the reported minimum but leaves the
// maximum, which callers rely on as a hard ceiling, untouched.
func TestJitter_Bounds(t *testing.T) {
	t.Parallel()

	s := backoff.Jitter(backoff.Linear(100*unit, 1000*unit), 0.5, nil)

	if got, want := s.MinDelay(), 50*unit; got != want {
		t.Errorf("min delay: got %v; want %v", got, want)
	}

	if got, want := s.MaxDelay(), 1000*unit; got != want {
		t.Errorf("max delay: got %v; want %v", got, want)
	}
}

// A strategy is stateless, so concurrent callers must never influence each
// other's delays.
func TestStrategy_ConcurrentUse(t *testing.T) {
	t.Parallel()

	s := backoff.New(backoff.WithJitterAmount(0))
	want := s.Delay(1)

	var wg sync.WaitGroup
	got := make([]time.Duration, 64)

	for i := range got {
		wg.Go(func() {
			for range 100 {
				got[i] = s.Delay(1)
			}
		})
	}
	wg.Wait()

	for i, d := range got {
		if d != want {
			t.Fatalf("goroutine %d: got %v; want %v", i, d, want)
		}
	}
}

// The default jitter source is shared by every strategy, so it must tolerate
// concurrent use just as the strategies themselves do.
func TestJitter_ConcurrentUse(t *testing.T) {
	t.Parallel()

	s := backoff.New(backoff.WithJitterAmount(0.5))

	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for n := range 100 {
				if d := s.Delay(n + 1); d < 0 {
					t.Errorf("delay: got %v; want a non-negative duration", d)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestCount(t *testing.T) {
	t.Parallel()

	s := backoff.Linear(100*unit, 1000*unit)
	a := backoff.Count(s)

	if got := a.Count(); got != 0 {
		t.Errorf("initial count: got %d; want 0", got)
	}

	want := delays(s, 3)
	got := []time.Duration{a.Next(), a.Next(), a.Next()}

	if !equal(got, want) {
		t.Errorf("delays: got %v; want %v", got, want)
	}

	if n := a.Count(); n != 3 {
		t.Errorf("count: got %d; want 3", n)
	}

	a.Reset()

	if n := a.Count(); n != 0 {
		t.Errorf("count after reset: got %d; want 0", n)
	}

	if d := a.Next(); d != want[0] {
		t.Errorf("delay after reset: got %v; want %v", d, want[0])
	}
}

func TestCount_NilStrategy(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("should have panicked")
		}
	}()

	backoff.Count(nil)
}

func TestWait(t *testing.T) {
	t.Parallel()

	start := time.Now()
	if err := backoff.Wait(t.Context(), 20*time.Millisecond); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("elapsed: got %v; want at least 20ms", elapsed)
	}
}

func TestWait_NonPositiveDuration(t *testing.T) {
	t.Parallel()

	for _, d := range []time.Duration{0, -time.Second} {
		if err := backoff.Wait(t.Context(), d); err != nil {
			t.Errorf("wait(%v): should not have returned an error: %v", d, err)
		}
	}
}

func TestWait_Canceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	errCh := make(chan error, 1)
	go func() { errCh <- backoff.Wait(ctx, time.Hour) }()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v; want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("did not return after cancellation")
	}
}

// A context that is already canceled must be reported even when there is no
// waiting left to do.
func TestWait_AlreadyCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	for _, d := range []time.Duration{0, time.Hour} {
		if err := backoff.Wait(ctx, d); !errors.Is(err, context.Canceled) {
			t.Errorf("wait(%v): got %v; want %v", d, err, context.Canceled)
		}
	}
}

func TestAttempts_Wait(t *testing.T) {
	t.Parallel()

	a := backoff.Count(backoff.Constant(0))

	if err := a.Wait(t.Context()); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if got := a.Count(); got != 1 {
		t.Errorf("count: got %d; want 1", got)
	}
}
