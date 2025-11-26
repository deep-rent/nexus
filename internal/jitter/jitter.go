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
var seeded Rand = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))

// Jitter applies random jitter to a duration.
type Jitter struct {
	p float64 // jitter percentage
	r Rand    // random number generator
}

// New creates a new Jitter instance with the given jitter percentage p
// (0.0 to 1.0) and random number generator r. If r is nil, a default seeded
// generator is used.
func New(p float64, r Rand) *Jitter {
	if r == nil {
		r = seeded // Fallback
	}
	return &Jitter{
		r: r,
		p: p,
	}
}

// Rand applies random jitter to the given duration d and returns the result.
func (j *Jitter) Rand(d time.Duration) time.Duration {
	return j.Damp(d, j.r.Float64())
}

// Damp applies jitter to the given duration d based on the factor f (0.0 to
// 1.0) and returns the result.
func (j *Jitter) Damp(d time.Duration, f float64) time.Duration {
	return time.Duration(float64(d) * (1 - f*j.p))
}
