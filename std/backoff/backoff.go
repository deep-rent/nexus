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

	"github.com/deep-rent/nexus/std/jitter"
)

const (
	// DefaultMinDelay is the default minimum time between consecutive retries.
	DefaultMinDelay = 1 * time.Second
	// DefaultMaxDelay is the default maximum time between consecutive retries.
	DefaultMaxDelay = 1 * time.Minute
	// DefaultGrowthFactor is the default growth factor in exponential backoff.
	DefaultGrowthFactor float64 = 2.0
	// DefaultJitterAmount is the default amount of jitter applied.
	DefaultJitterAmount float64 = 0.5
)

// Strategy defines the contract for a backoff algorithm.
//
// Implementations are stateless: the delay depends only on the attempt number
// passed to [Strategy.Delay], never on how often the strategy has been called
// before. They are therefore safe to share between concurrently retried
// operations, each of which counts its own attempts.
type Strategy interface {
	// Delay returns the duration to wait before attempt n, where n is 1 for
	// the first retry that follows the initial, failed attempt. Values below 1
	// are treated as 1. The result is bounded by [Strategy.MinDelay] and
	// [Strategy.MaxDelay].
	Delay(n int) time.Duration

	// MinDelay returns the lower bound for the durations returned by
	// [Strategy.Delay].
	MinDelay() time.Duration

	// MaxDelay returns the upper bound for the durations returned by
	// [Strategy.Delay].
	MaxDelay() time.Duration
}

// Rand is a minimal source of randomness used to compute jitter. It is
// satisfied by [math/rand/v2.Rand].
type Rand interface {
	// Float64 generates a pseudo-random number in [0.0, 1.0).
	Float64() float64
}

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

// New creates a backoff [Strategy] from the provided options.
//
// The returned strategy is exponential by default. It degrades to a linear
// strategy if the growth factor is one or less, and to a constant strategy if
// the minimum delay is not less than the maximum delay. Jitter, if any, is
// applied on top of whichever strategy is selected.
func New(opts ...Option) Strategy {
	c := config{
		minDelay:     DefaultMinDelay,
		maxDelay:     DefaultMaxDelay,
		growthFactor: DefaultGrowthFactor,
		jitterAmount: DefaultJitterAmount,
	}
	for _, opt := range opts {
		opt(&c)
	}

	var s Strategy
	switch {
	case c.minDelay >= c.maxDelay:
		s = &constant{delay: c.maxDelay}
	// Written as a negated comparison so that a growth factor of NaN, which
	// compares false against everything, also selects linear backoff.
	case !(c.growthFactor > 1):
		s = &linear{minDelay: c.minDelay, maxDelay: c.maxDelay}
	default:
		s = &exponential{
			minDelay:     c.minDelay,
			maxDelay:     c.maxDelay,
			growthFactor: c.growthFactor,
		}
	}

	return Jitter(s, c.jitterAmount, c.rand)
}

// Jitter decorates a [Strategy] so that its delays are randomly shortened,
// spreading retries of concurrent clients over time. The amount is a fraction
// between 0 and 1; a jittered delay is drawn from [d*(1-amount), d]. The
// strategy is returned unchanged if the amount is zero or less. If r is nil, a
// shared, auto-seeded generator is used.
func Jitter(s Strategy, amount float64, r Rand) Strategy {
	if amount <= 0 {
		return s
	}
	return &spread{s: s, j: jitter.New(min(1, amount), r)}
}
