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

// handler pairs a unique ID with a subscriber function for internal
// dispatching.
type handler[T any] struct {
	id uint64
	fn Subscriber[T]
}

// dispatcher defines the internal strategy for delivering events to
// subscribers.
type dispatcher[T any] interface {
	dispatch(event T, handlers []handler[T])
}

// syncDispatcher delivers events sequentially on the worker's goroutine.
type syncDispatcher[T any] struct{}

func (syncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		h.fn(event)
	}
}

// asyncDispatcher delivers events in parallel.
type asyncDispatcher[T any] struct{}

func (asyncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		go h.fn(event)
	}
}

// Option defines a functional configuration option for the Bus.
type Option[T any] func(*config[T])

type config[T any] struct {
	size       int
	policy     ring.OverflowPolicy
	dispatcher dispatcher[T]
}

// WithSize sets the ring buffer capacity.
// The provided size will be rounded up to the nearest power of 2. Non-negative
// values will be ignored.
func WithSize[T any](size int) Option[T] {
	return func(o *config[T]) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithOverflowPolicy sets the behavior when the internal ring buffer is full.
func WithOverflowPolicy[T any](policy ring.OverflowPolicy) Option[T] {
	return func(o *config[T]) {
		o.policy = policy
	}
}

// WithAsyncDispatch configures the bus to deliver events to subscribers
// concurrently. If this option is not provided, the bus defaults to
// synchronous dispatch.
func WithAsyncDispatch[T any]() Option[T] {
	return func(o *config[T]) {
		o.dispatcher = asyncDispatcher[T]{}
	}
}

// Bus represents a strictly-typed, lock-free event stream.
type Bus[T any] struct {
	buffer     *ring.Buffer[T]
	dispatcher dispatcher[T]
	subs       atomic.Pointer[[]handler[T]]
	mu         sync.Mutex
	id         uint64
	closed     atomic.Bool
	wg         sync.WaitGroup
}

// New creates a Bus, configured via functional options.
// If no options are provided, it defaults to a buffer size of 1024, the
// ring.Block overflow policy, and synchronous dispatching.
func New[T any](opts ...Option[T]) *Bus[T] {
	// Set default configuration
	cfg := config[T]{
		size:       1024,
		policy:     ring.Block,
		dispatcher: syncDispatcher[T]{},
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	b := &Bus[T]{
		buffer:     ring.New[T](cfg.size, cfg.policy),
		dispatcher: cfg.dispatcher,
	}

	empty := make([]handler[T], 0)
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

	b.id++
	id := b.id

	curr := *b.subs.Load()

	next := make([]handler[T], len(curr), len(curr)+1)
	copy(next, curr)
	next = append(next, handler[T]{id: id, fn: fn})

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
	next := make([]handler[T], 0, len(curr))

	for _, h := range curr {
		if h.id != id {
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
				b.dispatcher.dispatch(evt, handlers)
			}
		} else {
			if b.closed.Load() {
				return
			}
			runtime.Gosched()
		}
	}
}
