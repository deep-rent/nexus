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
//
// Usage:
//
//	bus := event.New[Event](event.WithSyncDispatch())
//	unsub := bus.Subscribe(func(e Event) {
//	    fmt.Println("Received:", e)
//	})
//	defer unsub()
//
//	bus.Publish(Event{Data: "Hello World"})
//	bus.Close()
package event

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deep-rent/nexus/internal/ring"
)

// OverflowMode determines how the bus behaves when the internal buffer is full.
type OverflowMode = ring.Policy

const (
	// Block waits until space is available in the buffer.
	Block = ring.Block
	// DropOldest removes the oldest unread event to make room for the new one.
	DropOldest = ring.DropOldest
	// DropNewest discards the incoming event if the buffer is full.
	DropNewest = ring.DropNewest
)

const (
	// DefaultSize is the default capacity of the internal ring buffer.
	DefaultSize = 1024
	// DefaultOverflowMode is the default overflow policy (Block).
	DefaultOverflowMode = Block
)

// Subscriber is a callback function that handles events of type T.
type Subscriber[T any] func(T)

// WaitStrategy defines the idling behavior of the background processor.
type WaitStrategy interface {
	// Snooze is called when the buffer is empty. The idle parameter
	// represents the number of consecutive empty polls.
	Snooze(idle int)
	// Signal awakens the processor from a Snooze.
	Signal()
}

type adaptiveWait struct{}

func (adaptiveWait) Snooze(idle int) {
	const (
		phase1 = 1000
		phase2 = 5000
	)
	if idle < phase1 {
		runtime.Gosched()
	} else if idle < phase2 {
		time.Sleep(time.Microsecond)
	} else {
		time.Sleep(time.Millisecond)
	}
}

func (adaptiveWait) Signal() {}

type blockingWait struct {
	sem chan struct{}
}

func (w *blockingWait) Snooze(_ int) { <-w.sem }

func (w *blockingWait) Signal() {
	select {
	case w.sem <- struct{}{}:
	default:
	}
}

type handler[T any] struct {
	id uint64
	fn Subscriber[T]
}

type dispatcher[T any] interface {
	dispatch(event T, handlers []handler[T])
}

type syncDispatcher[T any] struct{}

func (syncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		func() {
			defer func() { _ = recover() }()
			h.fn(event)
		}()
	}
}

type asyncDispatcher[T any] struct{}

func (asyncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		go func(f Subscriber[T]) {
			defer func() { _ = recover() }()
			f(event)
		}(h.fn)
	}
}

// Option configures the Bus during initialization.
type Option[T any] func(*config[T])

type config[T any] struct {
	size       int
	policy     OverflowMode
	dispatcher dispatcher[T]
	wait       WaitStrategy
}

// WithSize sets the buffer capacity (rounded up to the nearest power of 2).
func WithSize[T any](size int) Option[T] {
	return func(o *config[T]) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithOverflowMode defines the buffer behavior on exhaustion.
func WithOverflowMode[T any](policy OverflowMode) Option[T] {
	return func(o *config[T]) {
		o.policy = policy
	}
}

// WithSyncDispatch forces sequential event delivery.
func WithSyncDispatch[T any]() Option[T] {
	return func(o *config[T]) {
		o.dispatcher = syncDispatcher[T]{}
	}
}

// WithAdaptiveWait uses a low-latency spin-yield-sleep strategy.
func WithAdaptiveWait[T any]() Option[T] {
	return func(o *config[T]) {
		o.wait = adaptiveWait{}
	}
}

// WithBlockingWait uses a semaphore to park the CPU when idle.
func WithBlockingWait[T any]() Option[T] {
	return func(o *config[T]) {
		o.wait = &blockingWait{sem: make(chan struct{}, 1)}
	}
}

// WithCustomWaitStrategy injects a user-defined idling strategy.
// Nil values will be ignored.
func WithCustomWaitStrategy[T any](ws WaitStrategy) Option[T] {
	return func(o *config[T]) {
		if ws != nil {
			o.wait = ws
		}
	}
}

// Bus is a high-performance, strictly-typed event stream.
type Bus[T any] struct {
	buffer     *ring.Buffer[T]
	dispatcher dispatcher[T]
	wait       WaitStrategy
	subs       atomic.Pointer[[]handler[T]]
	closed     atomic.Bool

	mu sync.Mutex
	id uint64
	wg sync.WaitGroup
}

// New initializes a Bus with the provided options.
func New[T any](opts ...Option[T]) *Bus[T] {
	cfg := config[T]{
		size:       DefaultSize,
		policy:     DefaultOverflowMode,
		dispatcher: asyncDispatcher[T]{},
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

// Subscribe adds a callback to the bus. Returns an unsubscribe function.
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
	return func() { b.detach(id) }
}

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

// Publish pushes an event to the bus. Returns false if full or closed.
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

// Close drains remaining events and shuts down the background processor.
func (b *Bus[T]) Close() {
	b.closed.Store(true)
	b.wait.Signal()
	b.wg.Wait()
}

func (b *Bus[T]) process() {
	defer b.wg.Done()
	idle := 0
	for {
		if evt, ok := b.buffer.Pop(); ok {
			idle = 0
			if handlers := *b.subs.Load(); len(handlers) > 0 {
				b.dispatcher.dispatch(evt, handlers)
			}
		} else {
			if b.closed.Load() {
				for {
					if final, ok := b.buffer.Pop(); ok {
						if handlers := *b.subs.Load(); len(handlers) > 0 {
							b.dispatcher.dispatch(final, handlers)
						}
					} else {
						return
					}
				}
			}
			b.wait.Snooze(idle)
			idle++
		}
	}
}
