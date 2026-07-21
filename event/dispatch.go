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
	"runtime/debug"
	"sync"
)

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
// remaining subscribers from being notified. Completed deliveries and panics
// are counted separately.
func deliver[T any](
	logger *slog.Logger,
	stats *counters,
	fn Subscriber[T],
	event T,
) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(
				"Subscriber panicked",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())),
			)
			stats.add(stats.panics)
			return
		}
		stats.add(stats.delivered)
	}()
	fn(event)
}

// basicDispatcher delivers events sequentially on the background worker's
// goroutine.
type basicDispatcher[T any] struct {
	// logger records any panics triggered by a subscriber function.
	logger *slog.Logger
	// stats counts deliveries and panics.
	stats *counters
}

// dispatch iterates through all handlers and executes them sequentially.
func (d *basicDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		deliver(d.logger, d.stats, h.fn, event)
	}
}

// wait returns immediately: delivery already finished on the caller's
// goroutine.
func (d *basicDispatcher[T]) wait() {}

// asyncDispatcher delivers events concurrently by spawning a goroutine per
// subscriber.
type asyncDispatcher[T any] struct {
	// logger records any panics triggered by a subscriber function.
	logger *slog.Logger
	// stats counts deliveries and panics.
	stats *counters
	// wg tracks deliveries that have been started but not yet completed.
	wg sync.WaitGroup
}

// dispatch executes all handlers in parallel.
func (d *asyncDispatcher[T]) dispatch(event T, handlers []handler[T]) {
	for _, h := range handlers {
		d.wg.Add(1)
		go func(f Subscriber[T]) {
			defer d.wg.Done()
			deliver(d.logger, d.stats, f, event)
		}(h.fn)
	}
}

// wait blocks until every spawned delivery has returned.
func (d *asyncDispatcher[T]) wait() { d.wg.Wait() }

var (
	_ dispatcher[any] = &basicDispatcher[any]{}
	_ dispatcher[any] = &asyncDispatcher[any]{}
)
