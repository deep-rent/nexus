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

package backoff

import (
	"time"
)

// config holds the parameters for building a [Strategy] via [New].
type config struct {
	minDelay     time.Duration // lower bound for the delay
	maxDelay     time.Duration // upper bound for the delay
	growthFactor float64       // exponential multiplier per attempt
	jitterAmount float64       // fraction of the delay subject to jitter
	rand         Rand          // source of randomness for jitter
}

// Option customizes the behavior of a backoff [Strategy].
type Option func(*config)

// WithMinDelay sets the minimum time between consecutive retries, which is
// also the delay preceding the first retry. It is capped at zero (meaning no
// delay) if a negative duration is provided. If equal to or greater than the
// maximum delay, the backoff delays remain constant at the maximum delay. If
// not customized, [DefaultMinDelay] is used.
//
// When jitter is applied, the minimum delay is effectively reduced in
// proportion to the jitter amount. The strategy may therefore return a delay
// shorter than the configured minimum, depending on the random output.
func WithMinDelay(d time.Duration) Option {
	return func(c *config) {
		c.minDelay = max(0, d)
	}
}

// WithMaxDelay sets the maximum time between consecutive retries. It is capped
// at zero (meaning no delay) if a negative duration is provided. If less than
// or equal to the minimum delay, the backoff delays remain constant at the
// maximum delay. If not customized, [DefaultMaxDelay] is used.
func WithMaxDelay(d time.Duration) Option {
	return func(c *config) {
		c.maxDelay = max(0, d)
	}
}

// WithGrowthFactor determines the growth factor (multiplier) applied per
// attempt in exponential backoff. A factor of one or less selects linear
// backoff, where the minimum delay becomes the step size. A factor that is not
// a number is treated the same way. If not customized, [DefaultGrowthFactor]
// is used.
func WithGrowthFactor(f float64) Option {
	return func(c *config) {
		c.growthFactor = f
	}
}

// WithJitterAmount specifies the amount of random jitter to apply to the
// backoff delays. It is expressed as a fraction of the delay, where 0 means no
// jitter and 1 means full jitter. The given number is capped between 0 and 1.
// If not customized, [DefaultJitterAmount] is used.
//
// Jitter scatters retry attempts in time, which mitigates the thundering herd
// problem, where many clients retry simultaneously. It is subtractive: a
// jittered delay is drawn from [d*(1-amount), d], so the maximum delay is
// never exceeded.
func WithJitterAmount(p float64) Option {
	return func(c *config) {
		c.jitterAmount = min(1, max(0, p))
	}
}

// WithRand sets the source of randomness used to compute jitter. If not
// specified or nil, a shared, auto-seeded generator is used.
func WithRand(r Rand) Option {
	return func(c *config) {
		if r != nil {
			c.rand = r
		}
	}
}
