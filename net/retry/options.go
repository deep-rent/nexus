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

package retry

import (
	"github.com/deep-rent/nexus/std/backoff"
	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
)

// DefaultMaxDrainBytes is the default number of bytes read from the body of a
// failed attempt before the connection is given up on. Draining a body allows
// the underlying connection to be reused, but an unbounded read would let an
// oversized error page stall the retry loop.
const DefaultMaxDrainBytes int64 = 64 << 10 // 64 KB

// config holds the configuration parameters supplied via functional options.
type config struct {
	policy  Policy           // base retry logic
	limit   int              // maximum number of attempts
	backoff backoff.Strategy // supplies the delay between attempts
	logger  *log.Logger      // destination for debug output
	now     clock.Clock      // clock used to interpret date headers
	drain   int64            // bytes read from an abandoned response body
}

// Option is a function that configures the retry transport.
type Option func(*config)

// WithPolicy sets the retry policy used by the transport.
//
// If not provided, [DefaultPolicy] is used. A nil value is ignored.
func WithPolicy(policy Policy) Option {
	return func(c *config) {
		if policy != nil {
			c.policy = policy
		}
	}
}

// WithAttemptLimit sets the maximum number of attempts for a request.
//
// This includes the initial attempt. A value of 3 means one initial attempt
// and up to two retries. If the value is 0 or less, no limit is enforced,
// which makes the [Policy] and the request context solely responsible for
// ending the loop.
func WithAttemptLimit(n int) Option {
	return func(c *config) {
		c.limit = n
	}
}

// WithBackoff sets the strategy for calculating the delay between retries.
//
// Attempts are counted per request, so a single strategy can be shared by any
// number of concurrent requests without their delays interfering. If not
// provided, there is no delay between attempts. A nil value is ignored.
func WithBackoff(strategy backoff.Strategy) Option {
	return func(c *config) {
		if strategy != nil {
			c.backoff = strategy
		}
	}
}

// WithLogger sets the [log.Logger] for debug messages.
//
// If not provided, debug output is discarded ([log.Discard]). A nil value
// is ignored.
func WithLogger(logger *log.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithClock provides a custom time source used to interpret the date-based
// forms of the Retry-After and X-RateLimit-Reset headers, primarily for
// testing. It does not affect the actual waiting between attempts, which
// always follows the real clock.
//
// If not provided, [clock.System] is used. A nil value is ignored.
func WithClock(now clock.Clock) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// WithMaxDrainBytes limits how much of an abandoned response body is read
// before the next attempt. Draining lets the underlying connection be reused;
// bodies larger than this limit are closed instead, which costs a connection
// but bounds the work spent on a failed attempt.
//
// If not provided, [DefaultMaxDrainBytes] is used. A value of 0 or less
// disables draining entirely.
func WithMaxDrainBytes(n int64) Option {
	return func(c *config) {
		c.drain = n
	}
}
