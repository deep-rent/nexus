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
	"time"

	"github.com/deep-rent/nexus/internal/ring"
)

type Policy = ring.Policy

const (
	Block      = ring.Block
	DropOldest = ring.DropOldest
	DropNewest = ring.DropNewest
)

const (
	DefaultSize   = 1024
	DefaultPolicy = Block
)

type Subscriber[T any] func(T)

// WaitStrategy defines how the background processor behaves when the
// internal ring buffer is empty.
type WaitStrategy interface {
	// Wait is called continuously while the buffer is empty.
	Wait(idle int)
	// Signal is called whenever a new event is successfully published or
	// when the bus is closed.
	Signal()
}

// adaptiveWait employs spin-yield-sleep to minimize latency.
type adaptiveWait struct{}

func (adaptiveWait) Wait(idle int) {
	if idle < 1000 {
		runtime.Gosched()
	} else if idle < 5000 {
		time.Sleep(time.Microsecond)
	} else {
		time.Sleep(time.Millisecond)
	}
}

func (adaptiveWait) Signal() {} // No-op for spin loops

// blockingWait uses a semaphore channel to park the goroutine entirely
// when idle, saving CPU cycles at the cost of a slight wakeup latency.
type blockingWait struct {
	ch chan struct{}
}

func (w *blockingWait) Wait(_ int) {
	<-w.ch
}

func (w *blockingWait) Signal() {
	select {
	case w.ch <- struct{}{}:
	default:
	}
}

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
		func() {
			defer func() {
				if r := recover(); r != nil {
					// TODO: Pass to logger.
				}
			}()
			h.fn(event)
		}()
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
	policy     Policy
	dispatcher dispatcher[T]
	wait       WaitStrategy
}

// WithSize sets the ring buffer capacity.
// The provided size will be rounded up to the nearest power of 2. Non-positive
// values will be ignored.
func WithSize[T any](size int) Option[T] {
	return func(o *config[T]) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithPolicy sets the behavior when the internal ring buffer is full.
func WithPolicy[T any](policy Policy) Option[T] {
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

// WithAdaptiveWait configures the bus to prioritize ultra-low latency by
// spinning and yielding when idle. This is the default behavior.
func WithAdaptiveWait[T any]() Option[T] {
	return func(o *config[T]) {
		o.wait = adaptiveWait{}
	}
}

// WithBlockingWait configures the bus to park the background goroutine
// when idle. This is ideal when managing thousands of idle buses.
func WithBlockingWait[T any]() Option[T] {
	return func(o *config[T]) {
		o.wait = &blockingWait{ch: make(chan struct{}, 1)}
	}
}

// WithCustomWaitStrategy allows passing a user-defined WaitStrategy.
func WithCustomWaitStrategy[T any](ws WaitStrategy) Option[T] {
	return func(o *config[T]) {
		if ws != nil {
			o.wait = ws
		}
	}
}

// Bus represents a strictly-typed, lock-free event stream.
type Bus[T any] struct {
	// Hot path:

	buffer     *ring.Buffer[T]
	dispatcher dispatcher[T]
	wait       WaitStrategy
	subs       atomic.Pointer[[]handler[T]]
	closed     atomic.Bool

	// Cold path:

	mu sync.Mutex
	id uint64
	wg sync.WaitGroup
}

// New creates a Bus, configured via functional options.
// If no options are provided, it defaults to a buffer size of 1024, the
// ring.Block overflow policy, synchronous dispatching, and adaptive waiting.
func New[T any](opts ...Option[T]) *Bus[T] {
	// Set default configuration
	cfg := config[T]{
		size:       DefaultSize,
		policy:     DefaultPolicy,
		dispatcher: syncDispatcher[T]{},
		wait:       adaptiveWait{},
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	b := &Bus[T]{
		buffer:     ring.New[T](cfg.size, cfg.policy),
		dispatcher: cfg.dispatcher,
		wait:       cfg.wait,
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

// Publish attempts to push an event. Returns false if the buffer is full or
// closed.
func (b *Bus[T]) Publish(event T) bool {
	if b.closed.Load() {
		return false
	}
	if b.buffer.Push(event) {
		b.wait.Signal()
		return true
	}
	return false
}

// Close signals the background processor to drain remaining events and stop.
func (b *Bus[T]) Close() {
	b.closed.Store(true)
	b.wait.Signal() // Ensure the processor wakes up if it is blocking
	b.wg.Wait()
}

// process continuously polls the ring buffer for new events.
func (b *Bus[T]) process() {
	defer b.wg.Done()

	idle := 0

	for {
		if evt, ok := b.buffer.Pop(); ok {
			idle = 0 // Reset backoff on success

			handlers := *b.subs.Load()
			if len(handlers) > 0 {
				b.dispatcher.dispatch(evt, handlers)
			}
		} else {
			if b.closed.Load() {
				// Perform one final drain check after detecting the close signal.
				for {
					if final, ok := b.buffer.Pop(); ok {
						handlers := *b.subs.Load()
						if len(handlers) > 0 {
							b.dispatcher.dispatch(final, handlers)
						}
					} else {
						return // Truly empty and closed
					}
				}
			}

			b.wait.Wait(idle)
			idle++
		}
	}
}
