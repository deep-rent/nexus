// Package rotor provides a thread-safe, generic type for rotating
// through a slice of items in a round-robin fashion.
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
