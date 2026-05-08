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

// Package backoff provides customizable strategies for retrying operations
// with increasing delays.
//
// The core of the package is the [Strategy] interface, which computes the next
// backoff duration. Implementations are stateful; the [Strategy.Next] method
// returns progressively longer durations with each call. Once the retried
// operation is successful or abandoned, [Strategy.Done] must be called to reset
// the strategy's internal state.
//
// # Usage
//
// A default exponential backoff strategy with jitter can be created using the
// [New] function. The behavior can be customized using various [Option]
// functions, such as [WithMinDelay], [WithMaxDelay], [WithGrowthFactor], and
// [WithJitterAmount]. Jitter is added by default to prevent multiple clients
// from retrying in sync (the "thundering herd" problem), which can overwhelm a
// recovering service.
//
// Example:
//
//	s := backoff.New(
//		backoff.WithMinDelay(500*time.Millisecond),
//		backoff.WithMaxDelay(30*time.Second),
//	)
//	defer s.Done()
//
//	for {
//		err := doWork()
//		if err == nil {
//			break
//		}
//		time.Sleep(s.Next())
//	}
package backoff

import (
	"math"
	"sync/atomic"
	"time"

	"github.com/deep-rent/nexus/internal/jitter"
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
// Implementations of this interface are expected to be safe for concurrent use.
type Strategy interface {
	// Next returns the backoff duration for the upcoming retry attempt.
	// This method is stateful and returns incrementally larger durations based
	// on the number of times it has been called since the last call to Done.
	// The returned duration is bounded by [Strategy.MinDelay] and
	// [Strategy.MaxDelay].
	Next() time.Duration
	// Done resets the strategy's internal state, such as its attempt counter.
	// This must be called after the retried operation succeeds or is abandoned.
	Done()
	// MinDelay returns the lower bound for the backoff duration returned by Next.
	MinDelay() time.Duration
	// MaxDelay returns the upper bound for the backoff duration returned by Next.
	MaxDelay() time.Duration
}

// constant is a [Strategy] implementation that always returns a fixed delay.
type constant struct {
	// delay is the fixed duration returned by [constant.Next].
	delay time.Duration
}

// Constant produces a [Strategy] that always yields the same delay duration.
// If the provided delay is negative, it is treated as zero (meaning no delay).
func Constant(delay time.Duration) Strategy {
	return &constant{delay: max(0, delay)}
}

// Next returns the fixed delay for this [constant] strategy.
func (c *constant) Next() time.Duration { return c.delay }

// Done implements [Strategy.Done] but performs no action as [constant] is
// stateless.
func (c *constant) Done() {}

// MinDelay returns the fixed delay duration.
func (c *constant) MinDelay() time.Duration { return c.delay }

// MaxDelay returns the fixed delay duration.
func (c *constant) MaxDelay() time.Duration { return c.delay }

var _ Strategy = (*constant)(nil)

// linear is a [Strategy] implementation that increases delay linearly based
// on the attempt count.
type linear struct {
	// minDelay is the base step for the linear increment.
	minDelay time.Duration
	// maxDelay is the ceiling for the backoff duration.
	maxDelay time.Duration
	// attempts tracks the number of times [linear.Next] has been called.
	attempts atomic.Int64
}

// Next returns the backoff duration for the upcoming retry attempt.
func (l *linear) Next() time.Duration {
	n := l.attempts.Add(1)
	// If n is huge, simply return the delay limit to avoid overflow.
	if l.minDelay > 0 && n > int64(l.maxDelay/l.minDelay) {
		return l.maxDelay
	}
	d := l.minDelay * time.Duration(n)
	return max(l.minDelay, min(l.maxDelay, d))
}

// Done resets the attempt counter for the [linear] strategy.
func (l *linear) Done() { l.attempts.Store(0) }

// MinDelay returns the minimum delay configured for this [linear] strategy.
func (l *linear) MinDelay() time.Duration { return l.minDelay }

// MaxDelay returns the maximum delay configured for this [linear] strategy.
func (l *linear) MaxDelay() time.Duration { return l.maxDelay }

var _ Strategy = (*linear)(nil)

// exponential is a [Strategy] implementation that increases delay exponentially.
type exponential struct {
	// minDelay is the initial base duration before growth.
	minDelay time.Duration
	// maxDelay is the ceiling for the backoff duration.
	maxDelay time.Duration
	// growthFactor is the multiplier applied to each subsequent attempt.
	growthFactor float64
	// attempts tracks the number of times [exponential.Next] has been called.
	attempts atomic.Int64
}

// Next returns the backoff duration for the upcoming retry attempt.
func (e *exponential) Next() time.Duration {
	n := e.attempts.Add(1)
	d := time.Duration(float64(e.minDelay) * math.Pow(e.growthFactor, float64(n)))
	return max(e.minDelay, min(e.maxDelay, d))
}

// Done resets the attempt counter for the [exponential] strategy.
func (e *exponential) Done() { e.attempts.Store(0) }

// MinDelay returns the minimum delay configured for this [exponential] strategy.
func (e *exponential) MinDelay() time.Duration { return e.minDelay }

// MaxDelay returns the maximum delay configured for this [exponential] strategy.
func (e *exponential) MaxDelay() time.Duration { return e.maxDelay }

var _ Strategy = (*exponential)(nil)

// spread decorates a [Strategy] with jittering capabilities in order to spread
// out retry attempts over time.
type spread struct {
	// s is the underlying [Strategy] being jittered.
	s Strategy
	// j is the jitter implementation used to modify durations.
	j *jitter.Jitter
}

// Next returns the backoff duration from the underlying strategy after
// applying jitter.
func (s *spread) Next() time.Duration {
	return s.j.Apply(s.s.Next())
}

// Done resets the underlying strategy's state.
func (s *spread) Done() {
	s.s.Done()
}

// MinDelay returns the jittered lower bound of the underlying [Strategy].
func (s *spread) MinDelay() time.Duration {
	return s.j.Floor(s.s.MinDelay(), 1)
}

// MaxDelay returns the maximum delay of the underlying [Strategy].
// Jitter does not affect the maximum delay.
func (s *spread) MaxDelay() time.Duration {
	return s.s.MaxDelay()
}

var _ Strategy = (*spread)(nil)

// config holds the parameters for building a [Strategy] via [New].
type config struct {
	// minDelay is the minimum duration between retries.
	minDelay time.Duration
	// maxDelay is the maximum duration between retries.
	maxDelay time.Duration
	// growthFactor is the exponential multiplier.
	growthFactor float64
	// jitterAmount is the fraction of jitter to apply.
	jitterAmount float64
	// r is the source of randomness for jitter.
	r jitter.Rand
}

// Option customizes the behavior of a backoff [Strategy].
type Option func(*config)

// WithMinDelay sets the minimum time between consecutive retries.
// It is capped at zero (meaning no delay) if a negative duration is provided.
// If equal to or greater than the maximum delay, the backoff delays remain
// constant at the maximum delay. If not customized, the [DefaultMinDelay]
// is used.
//
// When jitter is introduced, the minimum delay is effectively reduced
// proportional to the jitter amount. Thus, the strategy might return a delay
// shorter than the configured minimum delay, depending on the random output.
func WithMinDelay(d time.Duration) Option {
	return func(c *config) {
		c.minDelay = max(0, d)
	}
}

// WithMaxDelay sets the maximum time between consecutive retries.
// It is capped at zero (meaning no delay) if a negative duration is provided.
// If less than or equal to the minimum delay, the backoff delays remain
// constant at the maximum delay. If not customized, the [DefaultMaxDelay]
// is used.
func WithMaxDelay(d time.Duration) Option {
	return func(c *config) {
		c.maxDelay = max(0, d)
	}
}

// WithGrowthFactor determines the growth factor (multiplier) for exponential
// backoff. A factor equal to one results in linear backoff, where the minimum
// delay becomes the step size. Any factor less than one is treated as one.
// If not customized, the [DefaultGrowthFactor] is used.
func WithGrowthFactor(f float64) Option {
	return func(c *config) {
		c.growthFactor = f
	}
}

// WithJitterAmount specifies the amount of random jitter to apply to the
// backoff delays. It is expressed as a fraction of the delay, where 0 means no
// jitter and 1 means full jitter. The given number is capped between 0 and 1.
// If not customized, the [DefaultJitterAmount] is used.
//
// Jitter scatters the retry attempts in time, which aims to mitigate the
// thundering herd problem, where many clients retry simultaneously.
func WithJitterAmount(p float64) Option {
	return func(c *config) {
		c.jitterAmount = min(1, p)
	}
}

// WithRand sets the source of randomness for jittering. If not specified or
// nil, a default source will be seeded with the current system time.
func WithRand(r jitter.Rand) Option {
	return func(c *config) {
		if r != nil {
			c.r = r
		}
	}
}

// New creates a new backoff [Strategy] based on the provided options.
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

	if c.minDelay >= c.maxDelay {
		return &constant{
			delay: c.maxDelay,
		}
	}

	if c.growthFactor <= 1 {
		return &linear{
			minDelay: c.minDelay,
			maxDelay: c.maxDelay,
		}
	}

	s := &exponential{
		minDelay:     c.minDelay,
		maxDelay:     c.maxDelay,
		growthFactor: c.growthFactor,
	}

	if c.jitterAmount <= 0 {
		return s
	}

	return &spread{
		s: s,
		j: jitter.New(c.jitterAmount, c.r),
	}
}
