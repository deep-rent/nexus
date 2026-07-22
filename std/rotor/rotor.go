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

package rotor

import (
	"math/rand/v2"
	"sync/atomic"
)

// Strategy represents the strategy type for selecting the next element in
// a [Rotor].
type Strategy int

const (
	// Sequential strategy picks the next element in a round-robin fashion.
	Sequential Strategy = iota
	// Random strategy chooses the next element randomly.
	Random
)

// strategy defines how the next element index is selected.
type strategy interface {
	// Pick returns the next element index given the total number of elements
	// available.
	Pick(n int) int
}

// sequential is a strategy that picks the next index in a round-robin fashion.
type sequential struct {
	idx atomic.Uint32
}

// Pick implements the Strategy interface.
func (s *sequential) Pick(n int) int {
	var idx uint32
	for {
		idx = s.idx.Load()
		if s.idx.CompareAndSwap(idx, (idx+1)%uint32(n)) { //nolint:gosec
			break
		}
	}
	return int(idx)
}

// random is a strategy that picks a random index.
type random struct{}

// Pick implements the Strategy interface.
func (r *random) Pick(n int) int {
	return rand.IntN(n) //nolint:gosec
}

// Rotor provides thread-safe round-robin access to a slice of items.
//
// It must be initialized with the [New] function. The interface allows for
// optimized internal implementations depending on the number of items provided.
type Rotor[E any] interface {
	// Next returns the next item in the rotation.
	// This method is safe for concurrent use by multiple goroutines.
	Next() E
}

// singleton is a [Rotor] that contains only a single item.
type singleton[E any] struct {
	// item is the solitary element in this rotation.
	item E
}

// Next implements the [Rotor] interface, always returning the same item.
func (s *singleton[E]) Next() E {
	return s.item
}

// rotor is a generic implementation of the [Rotor] interface for multiple
// items.
type rotor[E any] struct {
	// items is the immutable slice of elements to rotate through.
	items []E
	// strategy determines how the next item is selected.
	strategy strategy
}

// New creates a new [Rotor] with the given strategy and items to rotate
// through.
//
// It makes a defensive copy of the provided items slice to ensure immutability.
// This function panics if the items slice is empty. If the slice contains
// exactly one item, an optimized [Rotor] implementation will be created.
func New[E any](t Strategy, items []E) Rotor[E] {
	if len(items) == 0 {
		panic("items slice must not be empty")
	}
	if len(items) == 1 {
		return &singleton[E]{item: items[0]}
	}
	c := make([]E, len(items))
	copy(c, items)

	var s strategy
	switch t {
	case Random:
		s = &random{}
	case Sequential:
		fallthrough
	default:
		s = &sequential{}
	}

	return &rotor[E]{items: c, strategy: s}
}

// Next implements the [Rotor] interface.
//
// It uses the underlying strategy to determine the index of the next item.
func (r *rotor[E]) Next() E {
	return r.items[r.strategy.Pick(len(r.items))]
}

var _ Rotor[int] = (*rotor[int])(nil)
