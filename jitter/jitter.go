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

package jitter

import (
	"math/rand/v2"
	"time"
)

// Rand serves as a minimal facade over [rand.Rand] to ease mocking.
type Rand interface {
	// Float64 generates a pseudo-random number in [0.0, 1.0).
	Float64() float64
}

// Ensure compliance with parent interface.
var _ Rand = (*rand.Rand)(nil)

// global is a [Rand] backed by the top-level functions of [math/rand/v2].
//
// Unlike a [rand.Rand] value, which carries mutable state that a caller would
// have to guard, these are safe for concurrent use and auto-seeded by the
// runtime. That matters because a single [Jitter] is typically shared by every
// goroutine backing off against the same resource.
type global struct{}

// Float64 generates a pseudo-random number in [0.0, 1.0).
func (global) Float64() float64 { return rand.Float64() }

// seeded is the [Rand] used when no source is supplied.
var seeded Rand = global{}

// Jitter applies subtractive random jitter to a duration.
type Jitter struct {
	// p is the jitter percentage between 0.0 and 1.0.
	p float64
	// r is the random number generator source.
	r Rand
}

// New creates a new [Jitter] instance with the given percentage p (0.0 to 1.0)
// and source of randomness r.
//
// If r is nil, a shared generator that is safe for concurrent use is applied.
func New(p float64, r Rand) *Jitter {
	if r == nil {
		r = seeded // Fallback
	}
	return &Jitter{
		r: r,
		p: p,
	}
}

// Apply returns the duration d damped by a random amount based on the jitter
// percentage.
//
// The result is guaranteed to be in the range [[Jitter.Floor](d, 1.0), d].
func (j *Jitter) Apply(d time.Duration) time.Duration {
	return j.Floor(d, j.r.Float64())
}

// Floor returns the minimum possible duration that [Jitter.Apply] could return
// for the given input d when provided a random factor f.
//
// While typically used internally with f as a random float, passing f = 1.0
// provides the absolute lower bound for the jittered duration.
func (j *Jitter) Floor(d time.Duration, f float64) time.Duration {
	return time.Duration(float64(d) * (1 - f*j.p))
}
