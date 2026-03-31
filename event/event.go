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
// # Usage Example
//
//	package main
//
//	import (
//		"fmt"
//		"log/slog"
//		"time"
//		"github.com/deep-rent/nexus/event"
//	)
//
//	type UserCreated struct {
//		Email string
//	}
//
//	func main() {
//		// Initialize the bus with custom options
//		bus := event.New[UserCreated](
//			event.WithSyncDispatch[UserCreated](),
//			event.WithLogger[UserCreated](slog.Default()),
//		)
//		defer bus.Close()
//
//		// Subscribe to the event stream
//		unsub := bus.Subscribe(func(e UserCreated) {
//			fmt.Println("New user registered:", e.Email)
//		})
//		defer unsub() // Clean up subscriber when done
//
//		// Publish an event
//		bus.Publish(UserCreated{Email: "alice@example.com"})
//
//		// Allow a brief moment for asynchronous processes if needed
//		time.Sleep(time.Millisecond * 10)
//	}
package event

import (
	"log/slog"
	"runtime"
	"runtime/debug"
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
	// It is automatically rounded up to the nearest power of 2.
	DefaultSize = 1024
	// DefaultOverflowMode is the default overflow mode (Block).
	DefaultOverflowMode = Block
)

// Subscriber is a callback function that handles events of type T.
type Subscriber[T any] func(T)

// WaitStrategy defines the idling behavior of the background processor
// when the ring buffer is empty.
type WaitStrategy interface {
	// Snooze is called when the buffer is empty. The idle parameter
	// represents the number of consecutive empty polls.
	Snooze(idle int)
	// Signal awakens the processor from a Snooze when a new event arrives.
	Signal()
}

// adaptiveWait employs a spin-yield-sleep sequence to minimize latency
// while preventing constant CPU burn during idle periods.
type adaptiveWait struct{}

// Snooze scales the waiting mechanism based on how long the bus has been idle.
func (adaptiveWait) Snooze(idle int) {
	const (
		phase1 = 1000 // Spin-yield limit
		phase2 = 5000 // Micro-sleep limit
	)
	if idle < phase1 {
		// Low latency mode: Yield the processor but stay actively scheduled.
		runtime.Gosched()
	} else if idle < phase2 {
		// Cooldown mode: Drop CPU usage significantly while maintaining fast
		// response.
		time.Sleep(time.Microsecond)
	} else {
		// Deep idle mode: Near 0% CPU consumption.
		time.Sleep(time.Millisecond)
	}
}

// Signal is a no-op because the loop actively wakes itself up.
func (adaptiveWait) Signal() {}

// blockingWait uses a semaphore channel to park the goroutine entirely
// when idle, saving CPU cycles at the cost of a slight wakeup latency.
type blockingWait struct {
	// sem is a buffered channel acting as a non-blocking signaling mechanism.
	sem chan struct{}
}

// Snooze parks the goroutine until a value is received on the semaphore
// channel.
func (w *blockingWait) Snooze(_ int) { <-w.sem }

// Signal attempts to send a wakeup token. If the channel already has a token,
// it drops the send to avoid blocking the publisher.
func (w *blockingWait) Signal() {
	select {
	case w.sem <- struct{}{}:
	default:
	}
}

// handler pairs a unique identifier with a subscriber function for internal
// dispatching. The identifier allows for constant-time unsubscription without
// relying on function pointers.
type handler[T any] struct {
	id uint64
	fn Subscriber[T]
}

// dispatcher defines the internal strategy for delivering events to
// subscribers.
type dispatcher[T any] interface {
	dispatch(event T, handlers []handler[T])
}

// basicDispatcher delivers events sequentially on the background worker's
// goroutine.
type basicDispatcher[T any] struct {
	// logger records any panics triggered by a subscriber function.
	logger *slog.Logger
}

// dispatch iterates through all handlers and executes them sequentially.
func (d basicDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		// Isolate each handler call to prevent a panic in one subscriber
		// from crashing the entire background processor.
		func() {
			defer func() {
				if r := recover(); r != nil {
					d.logger.Error(
						"Subscriber panicked",
						slog.Any("panic", r),
						slog.String("stack", string(debug.Stack())),
					)
				}
			}()
			h.fn(event)
		}()
	}
}

// asyncDispatcher delivers events concurrently by spawning a goroutine per
// subscriber.
type asyncDispatcher[T any] struct {
	// logger records any panics triggered by a subscriber function.
	logger *slog.Logger
}

// dispatch executes all handlers in parallel.
func (d asyncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		go func(f Subscriber[T]) {
			defer func() {
				if r := recover(); r != nil {
					d.logger.Error(
						"Subscriber panicked",
						slog.Any("panic", r),
						slog.String("stack", string(debug.Stack())),
					)
				}
			}()
			f(event)
		}(h.fn)
	}
}

// Option configures the Bus during initialization.
type Option[T any] func(*config[T])

// config aggregates all user-defined settings for the Bus.
type config[T any] struct {
	size   int
	mode   OverflowMode
	sync   bool
	wait   WaitStrategy
	logger *slog.Logger
}

// WithSize sets the buffer capacity (rounded up to the nearest power of 2).
// Defaults to DefaultSize. Non-positive values will be ignored.
func WithSize[T any](size int) Option[T] {
	return func(o *config[T]) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithOverflowMode defines how the bus deals with backpressure on buffer
// exhaustion. Defaults to DefaultOverflowMode.
func WithOverflowMode[T any](mode OverflowMode) Option[T] {
	return func(o *config[T]) {
		o.mode = mode
	}
}

// WithSyncDispatch forces sequential event delivery. If omitted, the bus
// defaults to asynchronous parallel delivery.
func WithSyncDispatch[T any]() Option[T] {
	return func(o *config[T]) {
		o.sync = true
	}
}

// WithAdaptiveWait uses a low-latency spin-yield-sleep strategy.
// This is the default.
func WithAdaptiveWait[T any]() Option[T] {
	return func(o *config[T]) {
		o.wait = adaptiveWait{}
	}
}

// WithBlockingWait uses a semaphore to park the CPU when idle.
// Ideal for multi-tenant setups.
func WithBlockingWait[T any]() Option[T] {
	return func(o *config[T]) {
		o.wait = &blockingWait{sem: make(chan struct{}, 1)}
	}
}

// WithCustomWaitStrategy injects a user-defined idling strategy.
// Nil values are ignored.
func WithCustomWaitStrategy[T any](strategy WaitStrategy) Option[T] {
	return func(o *config[T]) {
		if strategy != nil {
			o.wait = strategy
		}
	}
}

// WithLogger sets the structured logger for recording subscriber panics.
// If not provided, it defaults to slog.Default().
func WithLogger[T any](logger *slog.Logger) Option[T] {
	return func(o *config[T]) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// Bus is a high-performance, strictly-typed event stream.
type Bus[T any] struct {
	// --- Hot path fields ---
	// These are accessed heavily by the background processor.

	// evts is the underlying lock-free ring buffer.
	evts *ring.Buffer[T]
	// disp is the configured strategy for calling subscriber functions.
	disp dispatcher[T]
	// wait dictates how the processor idles when the buffer is empty.
	wait WaitStrategy
	// subs is a copy-on-write pointer holding the active list of subscribers.
	subs atomic.Pointer[[]handler[T]]
	// closed indicates whether the bus has been shut down.
	closed atomic.Bool

	// --- Cold path fields ---
	// These are accessed only during subscription and teardown.

	// mu protects write operations to the active subscriber list.
	mu sync.Mutex
	// id is an incrementing counter providing unique keys for new subscribers.
	id uint64
	// wg tracks the lifecycle of the background processor goroutine.
	wg sync.WaitGroup
}

// NewBus initializes a Bus with the provided options.
func NewBus[T any](opts ...Option[T]) *Bus[T] {
	cfg := config[T]{
		size: DefaultSize,
		mode: DefaultOverflowMode,
		sync: false,
		wait: adaptiveWait{},
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}

	var disp dispatcher[T]
	if cfg.sync {
		disp = basicDispatcher[T]{
			logger: cfg.logger,
		}
	} else {
		disp = asyncDispatcher[T]{
			logger: cfg.logger,
		}
	}

	bus := &Bus[T]{
		evts: ring.New[T](cfg.size, cfg.mode),
		disp: disp,
		wait: cfg.wait,
	}

	// Seed the atomic pointer with an empty slice to avoid nil pointer panics on
	// first load.
	empty := make([]handler[T], 0)
	bus.subs.Store(&empty)

	// Spin up the background processor.
	bus.wg.Add(1)
	go bus.process()
	return bus
}

// Subscribe adds a callback to the bus. It returns an unsubscribe function
// that removes the callback when invoked.
func (b *Bus[T]) Subscribe(fn Subscriber[T]) (unsubscribe func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.id++
	id := b.id

	// Copy-on-write: Load current state, clone into a larger slice, and append.
	curr := *b.subs.Load()
	next := make([]handler[T], len(curr), len(curr)+1)
	copy(next, curr)
	next = append(next, handler[T]{id: id, fn: fn})

	// Atomically swap the new slice into place for the background processor to
	// read lock-free.
	b.subs.Store(&next)

	// Guarantee the teardown logic only runs exactly once.
	var once sync.Once
	return func() {
		once.Do(func() {
			b.detach(id)
		})
	}
}

// detach filters out the subscriber matching the given ID.
func (b *Bus[T]) detach(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	curr := *b.subs.Load()

	// Pre-allocate the new slice. By creating a new backing array, we ensure
	// the old array (and its function pointers) can be garbage collected.
	next := make([]handler[T], 0, len(curr))
	for _, h := range curr {
		if h.id != id {
			next = append(next, h)
		}
	}
	b.subs.Store(&next)
}

// Publish pushes an event to the bus. It returns false if the buffer is full
// (and DropNewest policy is active) or if the bus is already closed.
func (b *Bus[T]) Publish(event T) bool {
	// Guard against publishing to a stopped bus.
	if b.closed.Load() {
		return false
	}

	// Attempt to push to the lock-free ring buffer.
	if b.evts.Push(event) {
		// Awaken the processor if it happens to be snoozing.
		b.wait.Signal()
		return true
	}
	return false
}

// Close signals the background processor to drain remaining events and stop.
// Further calls to Publish will immediately return false.
//
// Note: Producers must be externally synchronized to stop calling Publish
// before Close is invoked to prevent stranded events.
func (b *Bus[T]) Close() {
	// Give straggling producers a few microseconds to finish their push
	// before we officially close the gates.
	time.Sleep(time.Microsecond * 50)

	// Atomically swap to closed. If it was already closed, do nothing.
	if !b.closed.Swap(true) {
		// Wake up the processor if it is blocking on a semaphore so it
		// can perform its final drain and exit.
		b.wait.Signal()

		// Wait for the processor goroutine to finish.
		b.wg.Wait()
	}
}

// process continuously polls the ring buffer for new events.
func (b *Bus[T]) process() {
	defer b.wg.Done()

	idle := 0

	for {
		// Fast path: attempt to pop an event off the lock-free queue.
		if evt, ok := b.evts.Pop(); ok {
			idle = 0 // Reset the backoff counter on success

			// Load a read-only snapshot of the subscribers.
			if handlers := *b.subs.Load(); len(handlers) > 0 {
				b.disp.dispatch(evt, handlers)
			}
		} else {
			// Slow path: queue is empty.
			if b.closed.Load() {
				// The bus was closed. Perform one final exhaustive drain check
				// in case events were published just before the close signal.
				for {
					if final, ok := b.evts.Pop(); ok {
						if handlers := *b.subs.Load(); len(handlers) > 0 {
							b.disp.dispatch(final, handlers)
						}
					} else {
						// Queue is truly empty and bus is closed; exit the goroutine.
						return
					}
				}
			}

			// Backoff and yield to prevent spinning the CPU at 100% capacity.
			b.wait.Snooze(idle)
			idle++
		}
	}
}
