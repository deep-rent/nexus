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
// It relies on a lock-free ring buffer for low-latency event publishing and an
// atomic copy-on-write mechanism for thread-safe subscriber management.
package event

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/deep-rent/nexus/internal/ring"
)

type Subscriber[T any] func(T)

// Handler pairs a unique ID with a subscriber function for use by the
// Dispatcher.
type Handler[T any] struct {
	ID uint64
	Fn Subscriber[T]
}

// Dispatcher defines the strategy for delivering events to subscribers.
type Dispatcher[T any] interface {
	Dispatch(event T, handlers []Handler[T])
}

// SyncDispatcher delivers events sequentially on the worker's goroutine.
type SyncDispatcher[T any] struct{}

func (SyncDispatcher[T]) Dispatch(event T, handlers []Handler[T]) {
	for _, h := range handlers {
		h.Fn(event)
	}
}

// AsyncDispatcher delivers events concurrently.
type AsyncDispatcher[T any] struct{}

func (AsyncDispatcher[T]) Dispatch(event T, handlers []Handler[T]) {
	for _, h := range handlers {
		go h.Fn(event)
	}
}

// Bus represents a strictly-typed, lock-free event stream.
type Bus[T any] struct {
	buffer     *ring.Buffer[T]
	dispatcher Dispatcher[T]

	subs  atomic.Pointer[[]Handler[T]]
	mu    sync.Mutex
	count uint64

	closed atomic.Bool
	wg     sync.WaitGroup
}

// New creates a Bus, configuring it with a buffer size, overflow policy,
// and dispatching strategy.
func New[T any](
	size int,
	policy ring.OverflowPolicy,
	dispatcher Dispatcher[T],
) *Bus[T] {
	b := &Bus[T]{
		buffer:     ring.New[T](size, policy),
		dispatcher: dispatcher,
	}

	empty := make([]Handler[T], 0)
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

	b.count++
	id := b.count

	curr := *b.subs.Load()

	next := make([]Handler[T], len(curr), len(curr)+1)
	copy(next, curr)
	next = append(next, Handler[T]{ID: id, Fn: fn})

	b.subs.Store(&next)

	return func() {
		b.detach(id)
	}
}

// detach filters out the subscriber with the given ID.
func (b *Bus[T]) detach(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	curr := *b.subs.Load()
	next := make([]Handler[T], 0, len(curr))

	for _, h := range curr {
		if h.ID != id {
			next = append(next, h)
		}
	}

	b.subs.Store(&next)
}

// Publish attempts to push an event into the underlying ring buffer.
func (b *Bus[T]) Publish(event T) bool {
	return b.buffer.Push(event)
}

// Close signals the background processor to drain remaining events and stop.
func (b *Bus[T]) Close() {
	b.closed.Store(true)
	b.wg.Wait()
}

// process continuously polls the ring buffer for new events.
func (b *Bus[T]) process() {
	defer b.wg.Done()

	for {
		if evt, ok := b.buffer.Pop(); ok {
			handlers := *b.subs.Load()
			if len(handlers) > 0 {
				b.dispatcher.Dispatch(evt, handlers)
			}
		} else {
			if b.closed.Load() {
				return
			}
			runtime.Gosched()
		}
	}
}
