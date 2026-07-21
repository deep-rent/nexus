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

package ring

import (
	"math/bits"
	"runtime"
	"sync/atomic"
)

// Policy dictates how the buffer behaves when a producer attempts to push into
// a queue that has reached its maximum capacity (overflow).
type Policy int

const (
	// Block causes the producer to yield the processor to other goroutines (via
	// [runtime.Gosched]) until space becomes available.
	Block Policy = iota

	// DropOldest forcefully advances the read pointer, discarding the oldest
	// unread item in the buffer to make room for the newly pushed item.
	DropOldest

	// DropNewest immediately discards the incoming item being pushed, returning
	// false and leaving the existing buffer contents unchanged.
	DropNewest
)

// Buffer represents a bounded, lock-free, strongly-typed concurrent queue.
type Buffer[T any] struct {
	// data holds the underlying circular storage for the buffer items.
	// Its length is always a power of two.
	data []T

	// seq holds the sequence numbers for each slot to prevent read-before-write
	// race conditions in concurrent MPMC scenarios.
	seq []uint64

	// head is a monotonically increasing counter representing the read index.
	// The actual array index is calculated as (head & mask).
	head atomic.Uint64

	// tail is a monotonically increasing counter representing the write index.
	// The actual array index is calculated as (tail & mask).
	tail atomic.Uint64

	// mask is used to perform a bitwise AND operation (tail & mask) to
	// wrap the counters around the buffer size efficiently.
	// It is equal to (capacity - 1).
	mask uint64

	// policy defines the behavior of the [Buffer.Push] operation when the
	// difference between tail and head reaches the buffer capacity.
	policy Policy
}

// New creates a [Buffer] configured with the requested size and overflow
// [Policy].
//
// If the provided size is less than 2, it defaults to 2. The final capacity is
// always automatically rounded up to the nearest power of two to optimize
// internal index masking via the [Buffer.mask].
func New[T any](size int, policy Policy) *Buffer[T] {
	if size < 2 {
		size = 2
	}
	// Round up to the next power of two.
	p := uint(1 << bits.Len(uint(size-1)))

	return &Buffer[T]{
		data:   make([]T, p),
		seq:    make([]uint64, p),
		mask:   uint64(p - 1),
		policy: policy,
	}
}

// Push adds an item to the tail of the buffer using atomic operations.
//
// It returns true if the item was successfully written. If the buffer is full
// and configured with the [DropNewest] policy, it safely discards the item and
// returns false. For the [Block] policy, it will wait for space by calling
// [runtime.Gosched].
func (b *Buffer[T]) Push(item T) bool {
	for {
		head := b.head.Load()
		tail := b.tail.Load()
		capacity := b.mask + 1

		// 1. Check if the buffer is full.
		if tail-head >= capacity {
			switch b.policy {
			case DropNewest:
				return false // Discard the incoming event
			case DropOldest:
				// Try to advance head to invalidate the oldest item.
				// If CAS fails, another goroutine already changed head; loop
				// and retry.
				b.head.CompareAndSwap(head, head+1)
				continue
			case Block:
				// Yield execution to the scheduler to allow consumers to
				// catch up.
				runtime.Gosched()
				continue
			}
		}

		// 2. Try to claim the tail slot.
		if b.tail.CompareAndSwap(tail, tail+1) {
			// 3. Write data to the claimed slot.
			b.data[tail&b.mask] = item
			// 4. Publish the write by updating the sequence number.
			atomic.StoreUint64(&b.seq[tail&b.mask], tail+1)
			return true
		}
		// CAS failed: another producer claimed the slot first; loop and retry.
	}
}

// Pop retrieves and removes the oldest item from the head of the buffer.
//
// It returns the generic item and true on success. If the buffer is currently
// empty, it returns the zero-value of type T and false. This method is safe
// for concurrent use by multiple consumers.
func (b *Buffer[T]) Pop() (T, bool) {
	var zero T // Used to return a zero-value on failure

	for {
		head := b.head.Load()
		tail := b.tail.Load()

		// 1. Check if the buffer is empty.
		if head == tail {
			return zero, false
		}

		// 2. Ensure the producer has finished writing to this slot.
		// If the sequence doesn't match head+1, it means the producer
		// claimed the tail but hasn't published the write yet, or we
		// are reading a stale head.
		if atomic.LoadUint64(&b.seq[head&b.mask]) != head+1 {
			runtime.Gosched()
			continue
		}

		// 3. Read the data BEFORE advancing the head pointer.
		item := b.data[head&b.mask]

		// 4. Try to commit the read.
		if b.head.CompareAndSwap(head, head+1) {
			return item, true
		}
		// CAS failed: another consumer popped the item first; loop and retry.
	}
}
