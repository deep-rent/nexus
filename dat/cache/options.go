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

package cache

import (
	"net/http"
	"time"

	"github.com/deep-rent/nexus/std/backoff"
	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
)

const (
	// DefaultMinInterval is the default lower bound for the refresh interval.
	DefaultMinInterval = 15 * time.Minute
	// DefaultMaxInterval is the default upper bound for the refresh interval.
	DefaultMaxInterval = 24 * time.Hour
	// DefaultRetryDelay is the default delay before the first retry after a
	// failed refresh. Subsequent failures back off exponentially, up to the
	// configured minimum interval.
	DefaultRetryDelay = 5 * time.Second
)

// config holds the internal configuration for the cache controller.
type config struct {
	minInterval time.Duration    // floor for refresh delays
	maxInterval time.Duration    // ceiling for refresh delays
	jitter      float64          // fraction of the interval subject to jitter
	backoff     backoff.Strategy // delays between failed refreshes
	logger      *log.Logger      // destination for internal logs
	client      *http.Client     // HTTP client used for fetching
	now         clock.Clock      // clock used to interpret date headers

	registry *metrics.Registry // records the refresh counter
}

// Option is a function that configures the cache [Controller].
type Option func(*config)

// WithClient sets the [http.Client] used to fetch the resource. Defaults to
// [transport.DefaultClient]. Nil values are ignored.
//
// The controller reads the response body in full, so the client is
// responsible for bounding its size. [transport.DefaultClient] does this;
// a client assembled elsewhere may not.
func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

// WithMinInterval sets the minimum duration between successful refreshes. The
// refresh delay, typically determined by caching headers, will not be shorter
// than this. It also serves as the ceiling for the retry backoff, so that a
// resource that keeps failing is not polled more often than a healthy one.
//
// Values of zero or less are ignored, and [DefaultMinInterval] is used
// instead.
func WithMinInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.minInterval = d
		}
	}
}

// WithMaxInterval sets the maximum duration between refreshes. The refresh
// delay will not be longer than this value. If it is shorter than the minimum
// interval, the minimum interval takes precedence.
//
// Values of zero or less are ignored, and [DefaultMaxInterval] is used
// instead.
func WithMaxInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.maxInterval = d
		}
	}
}

// WithJitterAmount scatters the refresh interval by a random fraction between
// 0 and 1, where 0 means no jitter and 1 means full jitter. The given number
// is capped to that range. If not customized, no jitter is applied.
//
// Jitter matters when many instances cache the same resource: without it, they
// tend to align on a shared expiry and refresh in lockstep, hitting the origin
// all at once. Since jitter only ever shortens an interval, an interval drawn
// this way may fall below the configured minimum.
func WithJitterAmount(p float64) Option {
	return func(c *config) {
		c.jitter = min(1, max(0, p))
	}
}

// WithBackoff sets the strategy that determines how long to wait after a
// failed refresh. Consecutive failures are counted, and the count resets as
// soon as a refresh succeeds.
//
// If not provided, an exponential strategy with jitter is used, starting at
// [DefaultRetryDelay] and capped at the configured minimum interval. A nil
// value is ignored.
func WithBackoff(strategy backoff.Strategy) Option {
	return func(c *config) {
		if strategy != nil {
			c.backoff = strategy
		}
	}
}

// WithLogger provides a custom [log.Logger] for the controller. If not
// provided, logging is disabled. A nil value is ignored.
func WithLogger(logger *log.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithRegistry sets the registry receiving the [Refreshes] counter, which
// counts refresh cycles by outcome ("updated", "unchanged", or "error") per
// resource URL. It defaults to [metrics.DefaultRegistry]. A nil value is
// ignored.
func WithRegistry(reg *metrics.Registry) Option {
	return func(c *config) {
		if reg != nil {
			c.registry = reg
		}
	}
}

// WithClock provides a custom time source used to interpret the date-based
// caching headers, primarily for testing. If not provided, [clock.System] is used.
// A nil value is ignored.
func WithClock(now clock.Clock) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}
