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
