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

package shed

import (
	"runtime/metrics"
	"time"

	"github.com/deep-rent/nexus/std/clock"
)

// config holds the configuration options for the shed middleware.
type config struct {
	interval   time.Duration
	fraction   float64
	retryAfter time.Duration
	memory     func() uint64
	now        clock.Clock
}

// Option configures the shed middleware.
type Option func(*config)

const (
	// DefaultInterval is the frequency at which the middleware checks memory
	// usage.
	DefaultInterval = 250 * time.Millisecond

	// DefaultThreshold is the fraction of GOMEMLIMIT at which the server begins
	// rejecting requests.
	DefaultThreshold = 0.90

	// DefaultRetryAfter is the default duration clients are asked to wait
	// before retrying, sent in the Retry-After header.
	DefaultRetryAfter = 5 * time.Second
)

// WithInterval sets the frequency at which the middleware checks memory usage.
// Nonpositive values will be ignored. Defaults to [DefaultInterval].
func WithInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithThreshold sets the fraction of GOMEMLIMIT at which the server begins
// rejecting requests. Numbers outside the interval (0,1] will be ignored.
// Defaults to [DefaultThreshold].
func WithThreshold(fraction float64) Option {
	return func(c *config) {
		if fraction > 0 && fraction <= 1.0 {
			c.fraction = fraction
		}
	}
}

// WithRetryAfter sets the duration clients should wait before retrying when the
// server sheds load. Nonpositive values will be ignored. Defaults to
// [DefaultRetryAfter].
func WithRetryAfter(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.retryAfter = d
		}
	}
}

// WithClock overrides the function used to get the current time. It is
// primarily useful for testing. Defaults to [clock.System] if left as nil.
func WithClock(now clock.Clock) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// WithMemoryProvider overrides the function used to query the current memory in
// use. It is primarily useful for testing. Defaults to reading the runtime
// metrics.
func WithMemoryProvider(provider func() uint64) Option {
	return func(c *config) {
		if provider != nil {
			c.memory = provider
		}
	}
}

// memory reads the current memory in use from the runtime metrics.
func memory() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	total := samples[0].Value.Uint64()
	released := samples[1].Value.Uint64()

	return max(0, total-released)
}
