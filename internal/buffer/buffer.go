// Package buffer provides a sync.Pool-backed implementation of
// httputil.BufferPool for reusing byte slices, aiming to save memory and
// reduce GC pressure when dealing with large response bodies.
package buffer

import (
	"net/http/httputil"
	"sync"
)

// Pool implements httputil.Pool backed by a sync.Pool internally.
// It reduces allocations for large response bodies by reusing byte slices,
// thus lowering GC pressure.
type Pool struct {
	pool sync.Pool
	size int
}

// NewPool creates a new Pool that returns buffers of at least minSize
// bytes. Buffers that grow beyond maxSize will be discarded.
//
// Both numbers must be positive, or else the function panics; minSize will be
// clamped by maxSize.
func NewPool(minSize, maxSize int) *Pool {
	if minSize <= 0 {
		panic("buffer: minSize must be positive")
	}
	if maxSize <= 0 {
		panic("buffer: maxSize must be positive")
	}
	minSize = min(minSize, maxSize)
	// Store a pointer to a slice to avoid allocations when storing in the
	// interface-typed pool
	alloc := func() any {
		buf := make([]byte, minSize)
		return &buf
	}
	return &Pool{
		pool: sync.Pool{New: alloc},
		size: maxSize,
	}
}

// Get returns a reusable buffer slice.
func (b *Pool) Get() []byte {
	//nolint:errcheck // The type assertion is guaranteed to succeed.
	return *b.pool.Get().(*[]byte)
}

// Put returns the buffer to the pool unless it grew beyond the size limit.
func (b *Pool) Put(buf []byte) {
	// Avoid holding on to overly large buffers
	if cap(buf) <= b.size {
		b.pool.Put(&buf)
	}
}

// Ensure Pool satisfies the httputil.BufferPool interface.
var _ httputil.BufferPool = (*Pool)(nil)
