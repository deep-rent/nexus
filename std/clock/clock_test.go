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

package clock_test

import (
	"testing"
	"time"

	"github.com/deep-rent/nexus/std/clock"
)

var epoch = time.Unix(1000, 0)

func TestClock_Now(t *testing.T) {
	t.Parallel()
	if exp, act := epoch, clock.Frozen(epoch).Now(); !exp.Equal(act) {
		t.Errorf("got %v; want %v", act, exp)
	}
}

func TestClock_Since(t *testing.T) {
	t.Parallel()
	c := clock.Frozen(epoch)
	if exp, act := time.Minute, c.Since(epoch.Add(-time.Minute)); exp != act {
		t.Errorf("got %v; want %v", act, exp)
	}
}

func TestClock_Until(t *testing.T) {
	t.Parallel()
	c := clock.Frozen(epoch)
	if exp, act := time.Minute, c.Until(epoch.Add(time.Minute)); exp != act {
		t.Errorf("got %v; want %v", act, exp)
	}
}

func TestClock_Offset(t *testing.T) {
	t.Parallel()
	c := clock.Frozen(epoch).Offset(time.Hour)
	if exp, act := epoch.Add(time.Hour), c.Now(); !exp.Equal(act) {
		t.Errorf("got %v; want %v", act, exp)
	}
}

func TestSystem(t *testing.T) {
	t.Parallel()
	// The system clock must advance monotonically with wall-clock time.
	before := time.Now()
	got := clock.System.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("got %v; want within [%v, %v]", got, before, after)
	}
}

func TestFrozen(t *testing.T) {
	t.Parallel()
	// A frozen clock reports the same instant on repeated reads.
	c := clock.Frozen(epoch)
	if exp, act := c.Now(), c.Now(); !exp.Equal(act) {
		t.Errorf("got %v; want %v", act, exp)
	}
}
