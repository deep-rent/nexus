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
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/schedule"
)

// A panicking tick must not take down the process, and must not take its
// siblings with it.
func TestScheduler_RecoversPanic(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var started, ran sync.Once
	panicked := make(chan struct{})
	survived := make(chan struct{})

	s := schedule.New(t.Context(), schedule.WithLogger(logger))

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		started.Do(func() { close(panicked) })
		panic("tick exploded")
	}))

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		ran.Do(func() { close(survived) })
		return time.Hour
	}))

	// Both must have run before shutting down, otherwise the scheduler may
	// stop before the panicking tick was ever scheduled.
	for _, ch := range []chan struct{}{panicked, survived} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("tick did not run")
		}
	}

	// Shutdown drains the goroutines, so the recovery has been logged by the
	// time it returns.
	s.Shutdown()

	logs := buf.String()
	tests := []struct {
		name string
		want string
	}{
		{"message", "Tick panicked"},
		{"value", "tick exploded"},
		{"stack", "schedule.(*scheduler).run"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(logs, tt.want) {
				t.Errorf("want match for %q; got %q", tt.want, logs)
			}
		})
	}
}

// A tick that panics on every run must not be retried in a tight loop.
func TestScheduler_RecoveryDelay(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		calls int
	)

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	s := schedule.New(t.Context(),
		schedule.WithLogger(logger),
		schedule.WithRecoveryDelay(time.Hour),
	)

	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		mu.Lock()
		calls++
		mu.Unlock()
		panic("always")
	}))

	time.Sleep(50 * time.Millisecond)
	s.Shutdown()

	mu.Lock()
	defer mu.Unlock()

	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}
}

// Once runs on the caller's stack, where a panic is the caller's to handle.
func TestOnce_PropagatesPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("should have panicked")
		}
	}()

	s := schedule.Once(t.Context())
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		panic("boom")
	}))
}

func TestOptions_IgnoreInvalidValues(t *testing.T) {
	t.Parallel()

	s := schedule.New(t.Context(),
		schedule.WithLogger(nil),
		schedule.WithRecoveryDelay(0),
		schedule.WithRecoveryDelay(-time.Second),
	)
	defer s.Shutdown()

	done := make(chan struct{})
	s.Dispatch(schedule.TickFn(func(context.Context) time.Duration {
		close(done)
		return time.Hour
	}))

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tick did not run")
	}
}
