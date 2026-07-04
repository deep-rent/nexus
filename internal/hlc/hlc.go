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

// Package hlc provides a Hybrid Logical Clock implementation.
//
// HLCs are used to generate causally ordered timestamps for distributed
// systems. They combine a physical wall-clock timestamp (in milliseconds)
// with a logical counter, fitting both into a single uint64.
package hlc

import (
	"errors"
	"sync"
	"time"
)

const (
	bits = 16
	mask = (1 << bits) - 1

	// maxOffset is the maximum physical clock drift allowed from remote peers
	// (e.g., 1 minute). Timestamps further in the future are rejected.
	maxOffset = 60000
)

// ErrClockDriftTooLarge is returned when updating the clock with a remote
// timestamp that is too far in the future compared to the local physical clock.
var ErrClockDriftTooLarge = errors.New(
	"hlc: remote clock drift exceeds maximum offset",
)

// ErrLogicalOverflow is returned when the logical counter space for a single
// millisecond is exhausted while applying a remote timestamp.
var ErrLogicalOverflow = errors.New("hlc: logical counter overflow")

// Pack combines physical milliseconds and logical counter into a single uint64.
func Pack(physical, logical uint64) uint64 {
	return (physical << bits) | (logical & mask)
}

// Unpack splits a packed uint64 into physical milliseconds and logical counter.
func Unpack(packed uint64) (physical, logical uint64) {
	return packed >> bits, packed & mask
}

// Clock is a thread-safe HLC instance.
type Clock struct {
	mu  sync.Mutex
	now func() time.Time
	l   uint64 // Highest physical millisecond observed
	c   uint64 // Logical counter
}

// New initializes a Clock to the current wall time.
// You may inject a custom time provider for testing; if nil, [time.Now] will be
// used instead.
func New(now func() time.Time) *Clock {
	if now == nil {
		now = time.Now
	}
	return &Clock{
		now: now,
		l:   uint64(now().UnixMilli()),
	}
}

// Now generates a new local HLC timestamp.
func (c *Clock) Now() uint64 {
	for {
		c.mu.Lock()
		pt := uint64(c.now().UnixMilli())

		// If wall clock is ahead, catch up and reset counter.
		if pt > c.l {
			c.l = pt
			c.c = 0
			res := Pack(c.l, c.c)
			c.mu.Unlock()
			return res
		}

		// Wall clock is behind or equal, increment logical counter.
		c.c++
		if c.c <= mask {
			res := Pack(c.l, c.c)
			c.mu.Unlock()
			return res
		}

		// Overflow prevention: release lock and wait until physical clock.
		// advances.
		target := c.l
		c.mu.Unlock()

		for uint64(c.now().UnixMilli()) <= target {
			time.Sleep(time.Millisecond)
		}
	}
}

// Update ticks the clock forward based on an incoming remote timestamp.
// It guarantees that the next generated local timestamp is greater than remote.
func (c *Clock) Update(remote uint64) (uint64, error) {
	rl, rc := Unpack(remote)
	pt := uint64(c.now().UnixMilli())

	// Prevent malicious/misconfigured clients from dragging the clock too far
	// forward.
	if rl > pt+maxOffset {
		return 0, ErrClockDriftTooLarge
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate the new physical time component.
	ln := max(rl, max(pt, c.l))

	// Calculate new logical counter.
	if ln == c.l && ln == rl { //nolint:gocritic
		c.c = max(c.c, rc) + 1
	} else if ln == c.l {
		c.c++
	} else if ln == rl {
		c.c = rc + 1
	} else {
		c.c = 0
	}
	c.l = ln

	// Handle counter overflow.
	if c.c > mask {
		return 0, ErrLogicalOverflow
	}

	return Pack(c.l, c.c), nil
}
