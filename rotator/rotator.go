// Package rotator provides a thread-safe, generic type for rotating
// through a slice of items in a round-robin fashion.
package rotator

import "sync/atomic"

// Rotator provides thread-safe round-robin access to a slice of items.
// It must be initialized with the New function.
type Rotator[E any] struct {
	items []E
	index atomic.Uint64
}

// New creates a new Rotator.
// It makes a defensive copy of the provided items slice to ensure immutability.
// This function panics if the items slice is empty.
func New[E any](items []E) *Rotator[E] {
	if len(items) == 0 {
		panic("rotator: items slice must not be empty")
	}
	c := make([]E, len(items))
	copy(c, items)
	return &Rotator[E]{items: c}
}

// Next returns the next item in the rotation.
// This method is safe for concurrent use by multiple goroutines.
func (r *Rotator[E]) Next() E {
	idx := r.index.Add(1)
	return r.items[(idx-1)%uint64(len(r.items))]
}
