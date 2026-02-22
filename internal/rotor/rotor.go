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

import "sync/atomic"

// Rotor provides thread-safe round-robin access to a slice of items.
// It must be initialized with the New function.
type Rotor[E any] interface {
	// Next returns the next item in the rotation.
	// This method is safe for concurrent use by multiple goroutines.
	Next() E
}

// singleton is a Rotor that contains only a single item.
type singleton[E any] struct{ item E }

// Next implements the Rotor interface.
func (s *singleton[E]) Next() E {
	return s.item
}

// rotor is a generic implementation of the Rotor interface.
type rotor[E any] struct {
	items []E
	index atomic.Uint64
}

// New creates a new Rotor.
// It makes a defensive copy of the provided items slice to ensure immutability.
// This function panics if the items slice is empty.
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

// Next implements the Rotor interface.
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
