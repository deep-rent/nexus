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
