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

type OverflowPolicy int

const (
	Block OverflowPolicy = iota
	DropOldest
	DropNewest
)

// Buffer is a lock-free ring buffer.
type Buffer[T any] struct {
	data   []T
	head   uint64
	tail   uint64
	mask   uint64 // Replaces capacity for bitwise modulo
	policy OverflowPolicy
}

// New creates a Buffer, rounding the size up to the nearest power of 2.
func New[T any](size int, policy OverflowPolicy) *Buffer[T] {
	if size < 2 {
		size = 2
	}
	// Round up to the next power of two
	p := 1 << bits.Len(uint(size-1))

	return &Buffer[T]{
		data:   make([]T, p),
		mask:   uint64(p - 1),
		policy: policy,
	}
}

// Push adds an item to the buffer lock-free.
func (b *Buffer[T]) Push(item T) bool {
	for {
		head := atomic.LoadUint64(&b.head)
		tail := atomic.LoadUint64(&b.tail)
		capacity := b.mask + 1

		// 1. Check if the buffer is full.
		if tail-head >= capacity {
			switch b.policy {
			case DropNewest:
				return false // Discard the incoming event
			case DropOldest:
				// Try to advance head to invalidate the oldest item.
				// If CAS fails, another goroutine already changed head; loop and retry.
				atomic.CompareAndSwapUint64(&b.head, head, head+1)
				continue
			case Block:
				// Yield execution to the scheduler to allow consumers to catch up.
				runtime.Gosched()
				continue
			}
		}

		// 2. Try to claim the tail slot
		if atomic.CompareAndSwapUint64(&b.tail, tail, tail+1) {
			// 3. Write data to the claimed slot
			b.data[tail&b.mask] = item
			return true
		}
		// CAS failed: another producer claimed the slot first; loop and retry.
	}
}

// Pop retrieves the oldest item from the buffer lock-free.
func (b *Buffer[T]) Pop() (T, bool) {
	var zero T // Used to return a zero-value on failure

	for {
		head := atomic.LoadUint64(&b.head)
		tail := atomic.LoadUint64(&b.tail)

		// 1. Check if the buffer is empty.
		if head == tail {
			return zero, false
		}

		// 2. Read the data BEFORE advancing the head pointer.
		item := b.data[head&b.mask]

		// 3. Try to commit the read
		if atomic.CompareAndSwapUint64(&b.head, head, head+1) {
			return item, true
		}
		// CAS failed: another consumer popped the item first; loop and retry.
	}
}
