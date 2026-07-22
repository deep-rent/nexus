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
	"math"
	"time"

	"github.com/deep-rent/nexus/std/jitter"
)

// clamp converts a delay computed in floating point to a [time.Duration]
// bounded by lo and hi.
//
// The comparison against hi is written as a negation so that it also holds for
// NaN and positive infinity, which [math.Pow] readily produces once the
// attempt count grows. This matters because converting an out-of-range float
// to an integer is implementation-defined in Go: on arm64 it saturates, while
// on amd64 it yields the smallest negative integer, which would silently
// collapse the backoff back to its minimum.
func clamp(f float64, lo, hi time.Duration) time.Duration {
	if !(f < float64(hi)) {
		return hi
	}
	return max(lo, time.Duration(f))
}

// constant is a [Strategy] implementation that always returns a fixed delay.
type constant struct {
	delay time.Duration // fixed duration returned for every attempt
}

// Constant produces a [Strategy] that always yields the same delay duration.
// If the provided delay is negative, it is treated as zero (meaning no delay).
func Constant(delay time.Duration) Strategy {
	return &constant{delay: max(0, delay)}
}

// Delay returns the fixed delay for this [constant] strategy.
func (c *constant) Delay(int) time.Duration { return c.delay }

// MinDelay returns the fixed delay duration.
func (c *constant) MinDelay() time.Duration { return c.delay }

// MaxDelay returns the fixed delay duration.
func (c *constant) MaxDelay() time.Duration { return c.delay }

var _ Strategy = (*constant)(nil)

// linear is a [Strategy] implementation that increases the delay linearly with
// the attempt number.
type linear struct {
	minDelay time.Duration // base step for the linear increment
	maxDelay time.Duration // ceiling for the backoff duration
}

// Linear produces a [Strategy] whose delay grows by minDelay with every
// attempt, so that attempt n waits for n*minDelay, capped at maxDelay.
// Negative durations are treated as zero. If minDelay is not less than
// maxDelay, the result is equivalent to [Constant] at maxDelay.
func Linear(minDelay, maxDelay time.Duration) Strategy {
	minDelay, maxDelay = max(0, minDelay), max(0, maxDelay)
	if minDelay >= maxDelay {
		return &constant{delay: maxDelay}
	}
	return &linear{minDelay: minDelay, maxDelay: maxDelay}
}

// Delay returns the backoff duration preceding attempt n.
func (l *linear) Delay(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	// Computed in floating point so that a large attempt count cannot overflow
	// the multiplication.
	return clamp(float64(l.minDelay)*float64(n), l.minDelay, l.maxDelay)
}

// MinDelay returns the minimum delay configured for this [linear] strategy.
func (l *linear) MinDelay() time.Duration { return l.minDelay }

// MaxDelay returns the maximum delay configured for this [linear] strategy.
func (l *linear) MaxDelay() time.Duration { return l.maxDelay }

var _ Strategy = (*linear)(nil)

// exponential is a [Strategy] implementation that increases the delay
// exponentially with the attempt number.
type exponential struct {
	minDelay     time.Duration // delay preceding the first retry
	maxDelay     time.Duration // ceiling for the backoff duration
	growthFactor float64       // multiplier applied per attempt
}

// Exponential produces a [Strategy] whose delay grows geometrically, so that
// attempt n waits for minDelay*factor^(n-1), capped at maxDelay. Negative
// durations are treated as zero. If minDelay is not less than maxDelay, or if
// factor is one or less, the result degrades to [Constant] or [Linear]
// respectively.
func Exponential(
	minDelay, maxDelay time.Duration,
	factor float64,
) Strategy {
	minDelay, maxDelay = max(0, minDelay), max(0, maxDelay)
	switch {
	case minDelay >= maxDelay:
		return &constant{delay: maxDelay}
	case !(factor > 1): // Also selects linear backoff for NaN.
		return &linear{minDelay: minDelay, maxDelay: maxDelay}
	default:
		return &exponential{
			minDelay:     minDelay,
			maxDelay:     maxDelay,
			growthFactor: factor,
		}
	}
}

// Delay returns the backoff duration preceding attempt n. The first retry
// waits for the minimum delay; every further attempt multiplies it by the
// growth factor.
func (e *exponential) Delay(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	f := float64(e.minDelay) * math.Pow(e.growthFactor, float64(n-1))
	return clamp(f, e.minDelay, e.maxDelay)
}

// MinDelay returns the minimum delay configured for this [exponential]
// strategy.
func (e *exponential) MinDelay() time.Duration { return e.minDelay }

// MaxDelay returns the maximum delay configured for this [exponential]
// strategy.
func (e *exponential) MaxDelay() time.Duration { return e.maxDelay }

var _ Strategy = (*exponential)(nil)

// spread decorates a [Strategy] with jitter in order to scatter retry attempts
// over time.
type spread struct {
	s Strategy       // underlying strategy being jittered
	j *jitter.Jitter // jitter implementation used to shorten durations
}

// Delay returns the delay of the underlying strategy, randomly shortened.
func (s *spread) Delay(n int) time.Duration {
	return s.j.Apply(s.s.Delay(n))
}

// MinDelay returns the jittered lower bound of the underlying [Strategy],
// which is the shortest delay it can possibly return.
func (s *spread) MinDelay() time.Duration {
	return s.j.Floor(s.s.MinDelay(), 1)
}

// MaxDelay returns the maximum delay of the underlying [Strategy]. Since
// jitter only ever shortens a delay, the upper bound is unaffected.
func (s *spread) MaxDelay() time.Duration {
	return s.s.MaxDelay()
}

var _ Strategy = (*spread)(nil)
