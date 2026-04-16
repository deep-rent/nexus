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

// Package rotor provides a thread-safe, generic type for rotating through a
// slice of items in a round-robin fashion.
//
// This package is intended for load-balancing scenarios, such as selecting
// backends, rotating API keys, or distributing tasks across a pool of workers.
// The implementation uses atomic operations to ensure high performance under
// concurrent access without the need for heavy-weight mutexes.
//
// # Usage
//
// Initialize a rotor with a slice of items and call Next to retrieve the next
// element in the sequence.
//
// Example:
//
//	backends := []string{"srv-1", "srv-2", "srv-3"}
//	r := rotor.New(backends)
//
//	// Each call returns the next item in the sequence, wrapping around
//	// at the end.
//	s1 := r.Next() // "srv-1"
//	s2 := r.Next() // "srv-2"
package rotor

import "sync/atomic"

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

// rotor is a generic implementation of the [Rotor] interface for multiple items.
type rotor[E any] struct {
	// items is the immutable slice of elements to rotate through.
	items []E
	// index tracks the current position in the rotation using atomic operations.
	index atomic.Uint64
}

// New creates a new [Rotor].
//
// It makes a defensive copy of the provided items slice to ensure immutability.
// This function panics if the items slice is empty. If the slice contains exactly
// one item, an optimized [Rotor] implementation is returned.
func New[E any](items []E) Rotor[E] {
	if len(items) == 0 {
		panic("rotor: items slice must not be empty")
	}
	if len(items) == 1 {
		return &singleton[E]{item: items[0]}
	}
	c := make([]E, len(items))
	copy(c, items)
	return &rotor[E]{items: c}
}

// Next implements the [Rotor] interface.
//
// It uses an atomic compare-and-swap loop to increment the internal index and
// wrap it around the length of the items slice, ensuring that every caller
// receives a unique index in the sequence until the cycle repeats.
func (r *rotor[E]) Next() E {
	n := uint64(len(r.items))
	var idx uint64
	for {
		idx = r.index.Load()
		if r.index.CompareAndSwap(idx, (idx+1)%n) {
			break
		}
	}
	return r.items[idx]
}
