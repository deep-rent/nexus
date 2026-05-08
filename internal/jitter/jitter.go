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

// Package jitter provides functionality for adding random variation (jitter) to
// time durations.
//
// This package is designed to help distributed systems avoid "thundering herd"
// problems by desynchronizing retry attempts or periodic jobs. The jitter
// implementation is "subtractive". It calculates a duration randomly chosen
// between [d * (1 - p), d], where p is the jitter percentage. This ensures that
// the returned duration never exceeds the input duration, allowing strict
// adherence to maximum delay limits (e.g., in backoff strategies).
//
// # Usage
//
// Create a [Jitter] instance with a specific percentage and apply it to your
// base durations.
//
// Example:
//
//	// Create a jitterer with 20% randomness.
//	j := jitter.New(0.2, nil)
//
//	// A 10s duration will result in a random value between 8s and 10s.
//	d := j.Apply(10 * time.Second)
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

// seeded is a pre-seeded [Rand] instance for default use.
//
// Note: Go 1.20+ auto-seeds the global RNG, which spares us from time-based
// seeding.
var seeded Rand = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) //nolint:gosec

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
