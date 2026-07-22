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
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/sys/schedule"
)

// tickSamples returns per-tick sample counts of the named metric.
func tickSamples(
	t *testing.T,
	reg *metrics.Registry,
	name string,
) map[string]uint64 {
	t.Helper()

	got := make(map[string]uint64)
	for _, s := range reg.Snapshot().Metrics {
		if s.Name != name {
			continue
		}
		switch s.Kind {
		case metrics.KindCounter:
			got[s.Tags["tick"]] = uint64(s.Value)
		default:
			got[s.Tags["tick"]] = s.Count
		}
	}
	return got
}

func TestRun_RecordsDuration(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	s := schedule.New(t.Context(), schedule.WithRegistry(reg))

	ran := make(chan struct{})
	s.Dispatch(schedule.Named("refresh", schedule.TickFn(
		func(context.Context) time.Duration {
			close(ran)
			return time.Hour
		},
	)))

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not run")
	}
	s.Shutdown()

	got := tickSamples(t, reg, schedule.TickDuration)
	if got["refresh"] != 1 {
		t.Errorf("durations: got %v; want refresh once", got)
	}
	if panics := tickSamples(t, reg, schedule.TickPanics); len(panics) != 0 {
		t.Errorf("panics: got %v; want none", panics)
	}
}

func TestRun_CountsPanics(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	s := schedule.New(t.Context(),
		schedule.WithLogger(log.Silent()),
		schedule.WithRegistry(reg),
	)

	ran := make(chan struct{})
	s.Dispatch(schedule.Named("broken", schedule.TickFn(
		func(context.Context) time.Duration {
			close(ran)
			panic("boom")
		},
	)))

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not run")
	}
	s.Shutdown()

	if got := tickSamples(t, reg, schedule.TickPanics); got["broken"] != 1 {
		t.Errorf("panics: got %v; want broken once", got)
	}

	// The panicked run still lands in the duration histogram.
	if got := tickSamples(t, reg, schedule.TickDuration); got["broken"] != 1 {
		t.Errorf("durations: got %v; want broken once", got)
	}
}

func TestRun_NamesUnnamedTicks(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	s := schedule.New(t.Context(), schedule.WithRegistry(reg))

	ran := make(chan struct{})
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		close(ran)
		return time.Hour
	}))

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not run")
	}
	s.Shutdown()

	got := tickSamples(t, reg, schedule.TickDuration)
	if got["schedule.tick"] != 1 {
		t.Errorf("durations: got %v; want schedule.tick once", got)
	}
}
