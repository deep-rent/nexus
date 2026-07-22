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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/event"
)

// Close must not return while a delivery it started is still running.
func TestBus_CloseWaitsForDeliveries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []event.Option
	}{
		{"async dispatch", nil},
		{"sync dispatch", []event.Option{event.WithSyncDispatch()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bus := event.NewBus[int](tt.opts...)

			var done atomic.Int64
			bus.Subscribe(func(int) {
				time.Sleep(50 * time.Millisecond)
				done.Add(1)
			})

			if !bus.Publish(1) {
				t.Fatal("publish: got false; want true")
			}

			bus.Close()

			if got := done.Load(); got != 1 {
				t.Errorf("completed deliveries: got %d; want 1", got)
			}
		})
	}
}

// Every event Publish accepted must reach the subscribers, even when Close
// runs concurrently with the publishers.
func TestBus_CloseDrainsConcurrentPublishers(t *testing.T) {
	t.Parallel()

	for range 20 {
		bus := event.NewBus[int](
			event.WithSyncDispatch(),
			event.WithSize(4096),
		)

		var received atomic.Int64
		bus.Subscribe(func(int) { received.Add(1) })

		var (
			wg       sync.WaitGroup
			accepted atomic.Int64
		)

		for range 4 {
			wg.Go(func() {
				for range 50 {
					if bus.Publish(1) {
						accepted.Add(1)
					}
				}
			})
		}

		// Close while the publishers are still going.
		time.Sleep(time.Millisecond)
		bus.Close()
		wg.Wait()

		if got, want := received.Load(), accepted.Load(); got != want {
			t.Fatalf("delivered: got %d; want %d accepted", got, want)
		}
	}
}

func TestBus_CloseIsIdempotent(t *testing.T) {
	t.Parallel()

	bus := event.NewBus[int]()
	bus.Close()
	bus.Close()

	if bus.Publish(1) {
		t.Error("publish after close: got true; want false")
	}
}

// Closing must not strand events that were buffered but not yet processed.
func TestBus_CloseDrainsBuffer(t *testing.T) {
	t.Parallel()

	const events = 500

	bus := event.NewBus[int](
		event.WithSyncDispatch(),
		event.WithSize(1024),
		event.WithBlockingWait(),
	)

	var received atomic.Int64
	bus.Subscribe(func(int) { received.Add(1) })

	accepted := 0
	for range events {
		if bus.Publish(1) {
			accepted++
		}
	}

	bus.Close()

	if got := received.Load(); got != int64(accepted) {
		t.Errorf("delivered: got %d; want %d", got, accepted)
	}
}
