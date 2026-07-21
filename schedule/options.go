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

package schedule

import (
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// DefaultRecoveryDelay is the default duration to wait before running a [Tick]
// again after it panicked. It keeps a job that fails immediately on every run
// from spinning.
const DefaultRecoveryDelay = 1 * time.Minute

// config holds the internal settings for the scheduler.
type config struct {
	logger         *slog.Logger         // destination for internal logs
	recovery       time.Duration        // delay applied after a tick panicked
	start          time.Duration        // delay before the first run of a tick
	jitter         float64              // fraction of the start delay subject to jitter
	minimum        time.Duration        // floor for the interval a tick asks for
	tracerProvider trace.TracerProvider // records a span per tick run
	meterProvider  metric.MeterProvider // records tick durations and panics
}

// Option is a function that configures the [Scheduler].
type Option func(*config)

// WithLogger provides a custom [slog.Logger] for the scheduler. It receives
// the report when a [Tick] panics. If not provided, [slog.Default] is used.
// A nil value is ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithTracerProvider sets the provider used to record a span per tick run.
// It defaults to the global provider registered with
// [go.opentelemetry.io/otel.SetTracerProvider], which is a no-op until an
// application installs a real one. A nil value is ignored.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) {
		if tp != nil {
			c.tracerProvider = tp
		}
	}
}

// WithMeterProvider sets the provider used to record tick durations and
// panics. It defaults to the global provider registered with
// [go.opentelemetry.io/otel.SetMeterProvider]. A nil value is ignored.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(c *config) {
		if mp != nil {
			c.meterProvider = mp
		}
	}
}

// WithRecoveryDelay sets how long the scheduler waits before running a [Tick]
// again after it panicked. Without a delay, a tick that panics on every run
// would be retried in a tight loop.
//
// Values of zero or less are ignored, and [DefaultRecoveryDelay] is used
// instead.
func WithRecoveryDelay(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.recovery = d
		}
	}
}

// WithStartDelay postpones the first run of every dispatched [Tick] by d.
// Without it, a tick runs as soon as it is dispatched. Subsequent runs are
// unaffected, since a tick sets its own cadence.
//
// Values of zero or less are ignored, and ticks start immediately.
func WithStartDelay(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.start = d
		}
	}
}

// WithStartJitter scatters the start delay by a random fraction between 0 and
// 1, where 0 means no jitter and 1 means the first run may land anywhere
// between dispatch and the full delay. The given number is capped to that
// range. If not customized, no jitter is applied.
//
// This matters for a fleet of instances that restart together: without a
// stagger they align on the same schedule and hit their dependencies in
// lockstep. Since jitter only ever shortens a delay, it has no effect unless
// [WithStartDelay] is set.
func WithStartJitter(p float64) Option {
	return func(c *config) {
		c.jitter = min(1, max(0, p))
	}
}

// WithMinInterval sets a floor for the interval a [Tick] asks for. A tick that
// returns a shorter duration, including zero, is rescheduled after this
// duration instead.
//
// Rescheduling without delay is a supported and occasionally useful pattern,
// for instance to drain a queue until it is empty. It is also the way to peg a
// core by accident: a tick that always returns zero is re-run as fast as the
// scheduler can call it. Set a floor on schedulers whose ticks are not trusted
// to converge.
//
// Values of zero or less are ignored, and ticks are rescheduled exactly as
// they ask.
func WithMinInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.minimum = d
		}
	}
}
