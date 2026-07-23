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
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
)

type Option func(*config)

// config aggregates all user-defined settings for the [Bus].
type config struct {
	// size is the internal buffer capacity.
	size int
	// mode is the behavior on buffer overflow.
	mode OverflowMode
	// sync determines if dispatching is sequential.
	sync bool
	// wait constructs the idling strategy for a bus's background worker. It is
	// a constructor rather than an instance so that every bus gets its own.
	wait func() WaitStrategy
	// logger is used for reporting errors and panics.
	logger *log.Logger
	// registry records the bus counters.
	registry *metrics.Registry
	// name distinguishes bus instances in the recorded metrics.
	name string
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
		o.wait = func() WaitStrategy { return adaptiveWait{} }
	}
}

// WithBlockingWait uses a semaphore to park the CPU when idle. Ideal for
// multi-tenant setups.
func WithBlockingWait() Option {
	return func(o *config) {
		o.wait = func() WaitStrategy {
			return &blockingWait{sem: make(chan struct{}, 1)}
		}
	}
}

// WithWaitStrategy injects a user-defined idling strategy.
//
// It takes a constructor rather than a strategy, because a [Broker] applies
// its options to every bus it creates and a strategy that carries state must
// not be shared between them. A single semaphore backing several buses, for
// instance, lets one bus consume the wakeup meant for another, leaving the
// other parked with an event already in its buffer.
//
// The constructor is invoked once per [Bus]. A nil constructor, or one that
// returns nil, is ignored.
func WithWaitStrategy(strategy func() WaitStrategy) Option {
	return func(o *config) {
		if strategy != nil {
			o.wait = strategy
		}
	}
}

// WithLogger sets the structured logger for recording subscriber panics. If
// not provided, the bus stays silent, as if [log.Discard] had been given.
func WithLogger(logger *log.Logger) Option {
	return func(o *config) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// WithRegistry sets the registry receiving the bus counters [BusPublished],
// [BusDropped], [BusDelivered], and [BusPanics]. It defaults to
// [metrics.DefaultRegistry]. A nil value is ignored.
func WithRegistry(reg *metrics.Registry) Option {
	return func(o *config) {
		if reg != nil {
			o.registry = reg
		}
	}
}

// WithName sets the value of the "bus" attribute on the recorded counters,
// keeping multiple buses apart in a telemetry backend. A [Broker] names every
// bus it creates after its topic, overriding this option.
func WithName(name string) Option {
	return func(o *config) {
		o.name = name
	}
}
