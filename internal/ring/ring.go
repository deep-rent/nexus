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

func (b *Buffer[T]) Push(item T) bool {
	return true
}
