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

// Rand serves as a minimal facade over rand.Rand to ease mocking.
type Rand interface {
	// Float64 generates a pseudo-random number in [0.0, 1.0).
	Float64() float64
}

// Ensure compliance with parent interface.
var _ Rand = (*rand.Rand)(nil)

// seeded is a pre-seeded Rand instance for default use.
// Note: Go 1.20+ auto-seeds the global RNG, which spares us from time-based
// seeding.
var seeded Rand = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))

// Jitter applies subtractive random jitter to a duration.
type Jitter struct {
	p float64 // jitter percentage
	r Rand    // random number generator
}

// New creates a new Jitter instance with the given percentage p (0.0 to 1.0)
// and source of randomness r.
//
// If r is nil, a default thread-safe, seeded generator is used.
func New(p float64, r Rand) *Jitter {
	if r == nil {
		r = seeded // Fallback
	}
	return &Jitter{
		r: r,
		p: p,
	}
}

// Apply returns the duration d damped by a random amount based on the
// jitter percentage.
//
// The result is guaranteed to be in the range [Floor(d), d].
func (j *Jitter) Apply(d time.Duration) time.Duration {
	return j.Floor(d, j.r.Float64())
}

// Floor returns the minimum possible duration that Apply could return for
// the given input d.
//
// This is equivalent to applying maximum jitter (factor = 1.0).
func (j *Jitter) Floor(d time.Duration, f float64) time.Duration {
	return time.Duration(float64(d) * (1 - f*j.p))
}
