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

// Package event provides a high-performance, in-memory event bus system.
//
// It relies on a lock-free ring buffer for low-latency event publishing and an
// atomic copy-on-write mechanism for thread-safe subscriber management. The
// package offers both standalone event streams ([Bus]) and a centralized topic
// manager ([Broker]) for safely routing different event types across an
// application.
//
// # Usage
//
// A typical setup involves initializing a [Broker], retrieving a typed [Bus]
// for a topic, and subscribing to or publishing events.
//
// Example:
//
//	type UserCreated struct {
//		Email string
//	}
//
//	// 1. Initialize the central broker with options.
//	broker := event.NewBroker(event.WithSyncDispatch())
//	defer broker.Close()
//
//	// 2. Retrieve a typed bus for a specific topic.
//	bus := event.Topic[UserCreated](broker, "users.created")
//
//	// 3. Subscribe to the event stream.
//	unsub := bus.Subscribe(func(e UserCreated) {
//		fmt.Println("New user registered:", e.Email)
//	})
//	defer unsub()
//
//	// 4. Publish an event.
//	bus.Publish(UserCreated{Email: "alice@example.com"})
package event

import (
	"fmt"
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
	// DefaultOverflowMode is the default overflow mode ([Block]).
	DefaultOverflowMode = Block
)

// Subscriber is a callback function that handles events of type T.
type Subscriber[T any] func(T)

// WaitStrategy defines the idling behavior of the background processor when the
// ring buffer is empty.
type WaitStrategy interface {
	// Snooze is called when the buffer is empty. The idle parameter represents
	// the number of consecutive empty polls.
	Snooze(idle int)
	// Signal awakens the processor from a Snooze when a new event arrives.
	Signal()
}

// adaptiveWait employs a spin-yield-sleep sequence to minimize latency while
// preventing constant CPU burn during idle periods.
type adaptiveWait struct{}

// Snooze scales the waiting mechanism based on how long the bus has been idle.
func (adaptiveWait) Snooze(idle int) {
	const (
		phase1 = 1000 // Spin-yield limit
		phase2 = 5000 // Sleep limit
	)

	switch {
	case idle < phase1:
		// Low latency mode: Yield the processor but stay actively scheduled.
		runtime.Gosched()
	case idle < phase2:
		// Cooldown mode: Drop CPU usage significantly while maintaining fast
		// response.
		time.Sleep(time.Microsecond)
	default:
		// Deep idle mode: Near 0% CPU consumption.
		time.Sleep(time.Millisecond)
	}
}

// Signal is a no-op because the loop actively wakes itself up.
func (adaptiveWait) Signal() {}

// blockingWait uses a semaphore channel to park the goroutine entirely when
// idle, saving CPU cycles at the cost of a slight wakeup latency.
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
	// id is a unique identifier for the subscriber.
	id uint64
	// fn is the callback function to be executed.
	fn Subscriber[T]
}

// dispatcher defines the internal strategy for delivering events to
// subscribers.
type dispatcher[T any] interface {
	// dispatch delivers the event to the provided list of handlers.
	dispatch(event T, handlers []handler[T])
	// wait blocks until every delivery this dispatcher started has finished.
	// It is called once the processor has stopped, so no further dispatch can
	// race with it.
	wait()
}

// deliver invokes a single subscriber, isolating the call so that a panic in
// one subscriber neither reaches the background processor nor keeps the
// remaining subscribers from being notified.
func deliver[T any](logger *slog.Logger, fn Subscriber[T], event T) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(
				"Subscriber panicked",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()
	fn(event)
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
		deliver(d.logger, h.fn, event)
	}
}

// wait returns immediately: delivery already finished on the caller's
// goroutine.
func (d basicDispatcher[T]) wait() {}

// asyncDispatcher delivers events concurrently by spawning a goroutine per
// subscriber.
type asyncDispatcher[T any] struct {
	// logger records any panics triggered by a subscriber function.
	logger *slog.Logger
	// wg tracks deliveries that have been started but not yet completed.
	wg sync.WaitGroup
}

// dispatch executes all handlers in parallel.
func (d *asyncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		d.wg.Add(1)
		go func(f Subscriber[T]) {
			defer d.wg.Done()
			deliver(d.logger, f, event)
		}(h.fn)
	}
}

// wait blocks until every spawned delivery has returned.
func (d *asyncDispatcher[T]) wait() { d.wg.Wait() }

// Option configures the [Bus] during initialization.
type Option func(*config)

// config aggregates all user-defined settings for the [Bus].
type config struct {
	// size is the internal buffer capacity.
	size int
	// mode is the behavior on buffer overflow.
	mode OverflowMode
	// sync determines if dispatching is sequential.
	sync bool
	// wait is the idling strategy for the background worker.
	wait WaitStrategy
	// logger is used for reporting errors and panics.
	logger *slog.Logger
}

// WithSize sets the buffer capacity (rounded up to the nearest power of 2).
// Defaults to [DefaultSize]. Non-positive values will be ignored.
func WithSize(size int) Option {
	return func(o *config) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithOverflowMode defines how the bus deals with backpressure on buffer
// exhaustion. Defaults to [DefaultOverflowMode].
func WithOverflowMode(mode OverflowMode) Option {
	return func(o *config) {
		o.mode = mode
	}
}

// WithSyncDispatch forces sequential event delivery. If omitted, the bus
// defaults to asynchronous parallel delivery.
func WithSyncDispatch() Option {
	return func(o *config) {
		o.sync = true
	}
}

// WithAdaptiveWait uses a low-latency spin-yield-sleep strategy. This is the
// default.
func WithAdaptiveWait() Option {
	return func(o *config) {
		o.wait = adaptiveWait{}
	}
}

// WithBlockingWait uses a semaphore to park the CPU when idle. Ideal for
// multi-tenant setups.
func WithBlockingWait() Option {
	return func(o *config) {
		o.wait = &blockingWait{sem: make(chan struct{}, 1)}
	}
}

// WithCustomWaitStrategy injects a user-defined idling strategy. Nil values are
// ignored. If passed to a [Broker], the instance is shared across all buses.
func WithCustomWaitStrategy(strategy WaitStrategy) Option {
	return func(o *config) {
		if strategy != nil {
			o.wait = strategy
		}
	}
}

// WithLogger sets the structured logger for recording subscriber panics. If not
// provided, it defaults to [slog.Default].
func WithLogger(logger *slog.Logger) Option {
	return func(o *config) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// Bus is a high-performance, strictly-typed event stream.
type Bus[T any] struct {
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
	// pubs counts publishers that passed the closed check but have not yet
	// finished pushing.
	pubs atomic.Int64
	// mu protects write operations to the active subscriber list.
	mu sync.Mutex
	// id is an incrementing counter providing unique keys for new subscribers.
	id uint64
	// wg tracks the lifecycle of the background processor goroutine.
	wg sync.WaitGroup
}

// NewBus initializes a [Bus] with the provided options.
func NewBus[T any](opts ...Option) *Bus[T] {
	cfg := config{
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
		disp = &asyncDispatcher[T]{
			logger: cfg.logger,
		}
	}

	bus := &Bus[T]{
		evts: ring.New[T](cfg.size, cfg.mode),
		disp: disp,
		wait: cfg.wait,
	}

	// Seed the atomic pointer with an empty slice to avoid nil pointer panics
	// on
	// first load.
	empty := make([]handler[T], 0)
	bus.subs.Store(&empty)

	// Spin up the background processor.
	bus.wg.Add(1)
	go bus.process()
	return bus
}

// Subscribe adds a callback to the bus. It returns an unsubscribe function that
// removes the callback when invoked.
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
// (and [DropNewest] policy is active) or if the bus is already closed.
//
// An event for which Publish reports true is guaranteed to reach the
// subscribers, even if [Bus.Close] is called concurrently.
func (b *Bus[T]) Publish(event T) bool {
	// Register as an in-flight publisher before consulting the flag, so that
	// Close cannot conclude the buffer is quiescent while this push is still
	// on its way in.
	b.pubs.Add(1)
	defer b.pubs.Add(-1)

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
// Further calls to [Bus.Publish] will immediately return false.
//
// Close blocks until every buffered event has been handed to the subscribers
// and, under the default asynchronous dispatch, until those deliveries have
// returned. It is safe to call more than once and safe to call concurrently
// with [Bus.Publish]: a publisher that has already been admitted completes
// before the drain begins.
func (b *Bus[T]) Close() {
	// Atomically swap to closed. If it was already closed, do nothing.
	if b.closed.Swap(true) {
		return
	}

	// Publishers admitted before the flag was set may still be on their way
	// into the ring buffer. Waiting for them here is what keeps the final
	// drain below from missing an event.
	for b.pubs.Load() > 0 {
		runtime.Gosched()
	}

	// Wake up the processor if it is blocking on a semaphore so it can
	// perform its final drain and exit.
	b.wait.Signal()

	// Wait for the processor goroutine to finish...
	b.wg.Wait()

	// ...and then for the deliveries it started.
	b.disp.wait()
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
						// Queue is truly empty and bus is closed; exit.
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
	// buses maps topic names to their underlying typed Bus instances.
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
