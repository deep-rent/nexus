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

package broker

import (
	"fmt"
	"sync"

	"github.com/deep-rent/nexus/event"
)

// closer is an internal interface that allows the Broker to shut down
// buses without knowing their generic type payloads.
type closer interface {
	Close()
}

// Broker manages a collection of typed event buses segregated by topic strings.
type Broker struct {
	mu    sync.RWMutex
	buses map[string]closer
}

// NewBroker initializes an empty event broker.
func NewBroker() *Broker {
	return &Broker{
		buses: make(map[string]closer),
	}
}

// Topic retrieves an existing bus for the given topic or creates a new one
// if it does not exist. It returns an error if the topic already exists but
// is registered to a different event type.
func Topic[T any](
	b *Broker,
	name string,
	opts ...event.Option[T],
) (*event.Bus[T], error) {
	// Fast path: Read-only lock
	b.mu.RLock()
	existing, exists := b.buses[name]
	b.mu.RUnlock()

	if exists {
		// Type assert back to the requested generic type
		bus, ok := existing.(*event.Bus[T])
		if !ok {
			return nil, fmt.Errorf(
				"event: topic %q exists but expects a different event type", name,
			)
		}
		return bus, nil
	}

	// Slow path: Write lock to initialize
	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check locking in case another goroutine initialized it
	// while we were waiting to acquire the write lock.
	if existing, exists = b.buses[name]; exists {
		bus, ok := existing.(*event.Bus[T])
		if !ok {
			return nil, fmt.Errorf(
				"event: topic %q exists but expects a different event type", name,
			)
		}
		return bus, nil
	}

	// Create and store the new typed bus
	bus := event.New[T](opts...)
	b.buses[name] = bus

	return bus, nil
}

// Close gracefully shuts down all buses managed by the broker.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, bus := range b.buses {
		bus.Close()
	}
	// Clear the map to release references.
	b.buses = make(map[string]closer)
}
