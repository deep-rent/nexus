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

package metrics

import (
	"math"
	"testing"
	"time"

	"github.com/deep-rent/nexus/std/clock"
)

// TestMeter_Rates drives the meter with a fake clock and checks the moving
// averages against the EWMA recurrence.
func TestMeter_Rates(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	m := newMeter()
	m.now = clock.Clock(func() time.Time { return now })
	m.started = now
	m.tick.Store(now.UnixNano())

	// 50 events in the first 5-second interval: 10 events per second.
	m.Mark(50)
	now = now.Add(tickInterval)

	rates := m.Rates()
	if got := rates.M01; math.Abs(got-10) > 1e-9 {
		t.Errorf("m1 after seed: got %v; want 10", got)
	}
	if got := rates.M15; math.Abs(got-10) > 1e-9 {
		t.Errorf("m15 after seed: got %v; want 10", got)
	}
	if got := rates.Mean; math.Abs(got-10) > 1e-9 {
		t.Errorf("mean: got %v; want 10", got)
	}

	// One idle interval decays the averages toward zero.
	now = now.Add(tickInterval)
	rates = m.Rates()
	want := 10 * (1 - alpha01)
	if got := rates.M01; math.Abs(got-want) > 1e-9 {
		t.Errorf("m1 after idle: got %v; want %v", got, want)
	}

	// The 15-minute window decays slower than the 1-minute window.
	if rates.M15 <= rates.M01 {
		t.Errorf("m15 (%v) should exceed m1 (%v)", rates.M15, rates.M01)
	}
}

// TestMeter_IdleGap ensures a long idle gap applies every missed interval
// rather than just one.
func TestMeter_IdleGap(t *testing.T) {
	t.Parallel()

	now := time.Unix(0, 0)
	m := newMeter()
	m.now = clock.Clock(func() time.Time { return now })
	m.started = now
	m.tick.Store(now.UnixNano())

	m.Mark(50)
	now = now.Add(tickInterval) // Seed at 10/s.
	_ = m.Rates()

	// Ten idle intervals: the average must have decayed ten times.
	now = now.Add(10 * tickInterval)
	want := 10.0
	for range 10 {
		want = ewma(want, 0, alpha01)
	}
	if got := m.Rates().M01; math.Abs(got-want) > 1e-9 {
		t.Errorf("m1 after gap: got %v; want %v", got, want)
	}
}
