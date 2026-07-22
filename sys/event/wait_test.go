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

package event_test

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/event"
)

// semaphore parks a processor until it is signalled, mirroring the built-in
// blocking strategy. Sharing one between buses is what this test guards
// against.
type semaphore struct{ sem chan struct{} }

func newSemaphore() *semaphore {
	return &semaphore{sem: make(chan struct{}, 1)}
}

func (w *semaphore) Snooze(int) { <-w.sem }

func (w *semaphore) Signal() {
	select {
	case w.sem <- struct{}{}:
	default:
	}
}

var _ event.WaitStrategy = (*semaphore)(nil)

// Each bus must idle on its own strategy. A shared semaphore lets one bus
// consume the wakeup meant for another, stranding an event that was already
// buffered.
func TestBroker_WaitStrategyIsPerBus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opt  event.Option
	}{
		{"blocking", event.WithBlockingWait()},
		{
			"custom",
			event.WithWaitStrategy(func() event.WaitStrategy {
				return newSemaphore()
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := event.NewBroker(tt.opt, event.WithSyncDispatch())
			defer b.Close()

			// Idle siblings park first, so a shared semaphore would hand them
			// the token meant for the bus published to below.
			for i := range 5 {
				_ = event.Topic[int](b, strconv.Itoa(i))
			}
			time.Sleep(20 * time.Millisecond)

			bus := event.Topic[int](b, "target")

			var got atomic.Int64
			bus.Subscribe(func(int) { got.Add(1) })

			time.Sleep(20 * time.Millisecond)

			if !bus.Publish(1) {
				t.Fatal("publish: got false; want true")
			}

			deadline := time.After(2 * time.Second)
			for got.Load() == 0 {
				select {
				case <-deadline:
					t.Fatal("event was never delivered; wakeup was stolen")
				default:
					time.Sleep(time.Millisecond)
				}
			}
		})
	}
}

// A constructor that misbehaves must not leave the bus without a strategy.
func TestBus_WaitStrategyFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opt  event.Option
	}{
		{"nil constructor", event.WithWaitStrategy(nil)},
		{
			"constructor returning nil",
			event.WithWaitStrategy(func() event.WaitStrategy { return nil }),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bus := event.NewBus[int](tt.opt, event.WithSyncDispatch())
			defer bus.Close()

			var got atomic.Int64
			bus.Subscribe(func(int) { got.Add(1) })

			if !bus.Publish(1) {
				t.Fatal("publish: got false; want true")
			}

			bus.Close()

			if n := got.Load(); n != 1 {
				t.Errorf("delivered: got %d; want 1", n)
			}
		})
	}
}
