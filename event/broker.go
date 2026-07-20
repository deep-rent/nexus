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

package event

import (
	"fmt"
	"sync"
)

// closer is an internal interface that allows the [Broker] to shut down buses
// without knowing their generic type payloads.
type closer interface {
	// Close signals the resource to shut down.
	Close()
}

// Broker manages a collection of typed event buses segregated by topic strings.
type Broker struct {
	// mu protects the buses map and the closed flag.
	mu sync.RWMutex
	// buses maps topic names to their underlying typed [Bus] instances.
	buses map[string]closer
	// closed indicates whether the broker has been shut down.
	closed bool
	// opts are the default options applied to all buses created by this broker.
	opts []Option
}

// NewBroker initializes an empty event [Broker] with options applied to all
// subsequently created buses.
func NewBroker(opts ...Option) *Broker {
	return &Broker{
		buses: make(map[string]closer),
		opts:  opts,
	}
}

// Topic retrieves an existing [Bus] for the given topic or creates a new one
// using the broker's configured options. It panics if the topic already exists
// but is registered to a different event type.
//
// Once the broker has been closed it owns no buses, so Topic hands back an
// already closed [Bus] that accepts no events. This keeps a shutdown racing
// with a late caller from silently starting a processor that nothing will ever
// stop.
func Topic[T any](b *Broker, name string) *Bus[T] {
	// Fast path: Invoke the read-only lock.
	b.mu.RLock()
	existing, exists := b.buses[name]
	closed := b.closed
	b.mu.RUnlock()

	if exists {
		return cast[T](existing, name)
	}

	if closed {
		return closedBus[T]()
	}

	// Slow path: Invoke the write lock to initialize.
	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check locking in case another goroutine initialized it, or closed
	// the broker, while we were waiting to acquire the write lock.
	if existing, exists = b.buses[name]; exists {
		return cast[T](existing, name)
	}

	if b.closed {
		return closedBus[T]()
	}

	// Create and store the new typed bus.
	bus := NewBus[T](b.opts...)
	b.buses[name] = bus

	return bus
}

// cast converts a registered bus back to its requested generic type, panicking
// if the topic was registered for a different event type.
func cast[T any](existing closer, name string) *Bus[T] {
	bus, ok := existing.(*Bus[T])
	if !ok {
		panic(fmt.Sprintf(
			"topic %q exists but expects a different event type",
			name,
		))
	}
	return bus
}

// closedBus returns a [Bus] that is already shut down, so that it holds no
// running goroutine and rejects every publish.
func closedBus[T any]() *Bus[T] {
	bus := NewBus[T]()
	bus.Close()
	return bus
}

// Close gracefully shuts down all buses managed by the broker. It blocks until
// every bus has drained, and is safe to call more than once.
//
// After Close returns, [Topic] no longer creates buses; see its documentation.
func (b *Broker) Close() {
	b.mu.Lock()
	// 1. Capture the existing buses.
	buses := b.buses
	// 2. Clear the map to release references and block new retrievals.
	b.buses = make(map[string]closer)
	b.closed = true
	b.mu.Unlock() // Release the lock before calling Close on all the buses

	// 3. Close all buses concurrently so that their drains overlap.
	var wg sync.WaitGroup
	for _, bus := range buses {
		wg.Go(bus.Close)
	}
	wg.Wait()
}
