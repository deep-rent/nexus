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
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel"

	"github.com/deep-rent/nexus/ring"
)

// OverflowMode determines how the bus behaves when the internal buffer is
// full. An unrecognized value is treated as [Block].
type OverflowMode ring.Policy

const (
	// Block waits until space is available in the buffer.
	Block = OverflowMode(ring.Block)
	// DropOldest removes the oldest unread event to make room for the new one.
	DropOldest = OverflowMode(ring.DropOldest)
	// DropNewest discards the incoming event if the buffer is full.
	DropNewest = OverflowMode(ring.DropNewest)
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
	// stats counts published and dropped events.
	stats *counters
}

// NewBus initializes a [Bus] with the provided options.
func NewBus[T any](opts ...Option) *Bus[T] {
	cfg := config{
		size: DefaultSize,
		mode: DefaultOverflowMode,
		sync: false,
		wait: func() WaitStrategy { return adaptiveWait{} },
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	if cfg.meterProvider == nil {
		cfg.meterProvider = otel.GetMeterProvider()
	}
	stats := newCounters(cfg.meterProvider, cfg.name)

	// Every bus idles on its own strategy, so that a stateful one cannot be
	// shared by the buses a broker creates.
	wait := cfg.wait()
	if wait == nil {
		wait = adaptiveWait{}
	}

	var disp dispatcher[T]
	if cfg.sync {
		disp = basicDispatcher[T]{
			logger: cfg.logger,
			stats:  stats,
		}
	} else {
		disp = &asyncDispatcher[T]{
			logger: cfg.logger,
			stats:  stats,
		}
	}

	bus := &Bus[T]{
		evts:  ring.New[T](cfg.size, ring.Policy(cfg.mode)),
		disp:  disp,
		wait:  wait,
		stats: stats,
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
		b.stats.add(b.stats.dropped)
		return false
	}

	// Attempt to push to the lock-free ring buffer.
	if b.evts.Push(event) {
		// Awaken the processor if it happens to be snoozing.
		b.wait.Signal()
		b.stats.add(b.stats.published)
		return true
	}
	b.stats.add(b.stats.dropped)
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
