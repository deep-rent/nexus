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

// Package event provides a high-performance, in-memory event bus.
// It uses a lock-free ring buffer for low-latency event publishing and an
// atomic copy-on-write mechanism for thread-safe subscriber management.
package event

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/deep-rent/nexus/internal/ring"
)

type Subscriber[T any] func(T)

// Dispatcher defines the strategy for delivering events to subscribers.
type Dispatcher[T any] interface {
	Dispatch(event T, subscribers []Subscriber[T])
}

// SyncDispatcher delivers events sequentially on the worker's goroutine.
// It blocks the bus from processing the next event until all subscribers
// finish.
type SyncDispatcher[T any] struct{}

func (SyncDispatcher[T]) Dispatch(event T, subs []Subscriber[T]) {
	for _, sub := range subs {
		sub(event)
	}
}

// AsyncDispatcher delivers events concurrently, spawning a new goroutine
// for each subscriber.
type AsyncDispatcher[T any] struct{}

func (AsyncDispatcher[T]) Dispatch(event T, subs []Subscriber[T]) {
	for _, sub := range subs {
		go sub(event)
	}
}

// subscriber holds a subscriber function and a unique ID for removal.
type subscriber[T any] struct {
	id uint64
	fn Subscriber[T]
}

// Bus represents a strictly-typed, lock-free event stream.
type Bus[T any] struct {
	buffer     *ring.Buffer[T]
	dispatcher Dispatcher[T]

	subs  atomic.Pointer[[]subscriber[T]]
	mu    sync.Mutex
	count uint64

	done chan struct{}
	wg   sync.WaitGroup
}

// New creates a Bus, configuring it with a buffer size, overflow policy,
// and dispatching strategy. It automatically starts the background processor.
func New[T any](
	size int,
	policy ring.OverflowPolicy,
	dispatcher Dispatcher[T],
) *Bus[T] {
	b := &Bus[T]{
		buffer:     ring.New[T](size, policy),
		dispatcher: dispatcher,
		done:       make(chan struct{}),
	}

	// Initialize the atomic pointer with an empty slice to prevent nil panics.
	empty := make([]subscriber[T], 0)
	b.subs.Store(&empty)

	b.wg.Add(1)
	go b.process()

	return b
}

// Subscribe registers a callback for events and returns a function
// that can be called to remove the subscription.
func (b *Bus[T]) Subscribe(fn Subscriber[T]) (unsubscribe func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	id := atomic.AddUint64(&b.count, 1)

	// Copy-on-write: read current, copy to new, append, and atomic swap.
	current := *b.subs.Load()
	next := make([]subscriber[T], len(current), len(current)+1)
	copy(next, current)
	next = append(next, subscriber[T]{id: id, fn: fn})

	b.subs.Store(&next)

	return func() {
		b.detach(id)
	}
}

// detach filters out the subscriber with the given ID.
func (b *Bus[T]) detach(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	current := *b.subs.Load()
	next := make([]subscriber[T], 0, len(current))

	for _, sub := range current {
		if sub.id != id {
			next = append(next, sub)
		}
	}

	b.subs.Store(&next)
}

// Publish attempts to push an event into the underlying ring buffer.
// It returns true if successful, or false if the buffer is full and
// configured with the DropNewest policy.
func (b *Bus[T]) Publish(event T) bool {
	return b.buffer.Push(event)
}

// Close signals the background processor to stop and waits for it to halt.
func (b *Bus[T]) Close() {
	close(b.done)
	b.wg.Wait()
}

// process continuously polls the ring buffer for new events.
func (b *Bus[T]) process() {
	defer b.wg.Done()

	for {
		select {
		case <-b.done:
			return
		default:
			// Attempt to pop lock-free.
			if item, ok := b.buffer.Pop(); ok {
				curr := *b.subs.Load()
				if len(curr) == 0 {
					continue // No subscribers
				}

				// Extract raw functions for the dispatcher.
				subs := make([]Subscriber[T], len(curr))
				for i, s := range curr {
					subs[i] = s.fn
				}

				b.dispatcher.Dispatch(item, subs)
			} else {
				// The queue is empty. Yield the thread to prevent the loop
				// from starving the CPU.
				runtime.Gosched()
			}
		}
	}
}
