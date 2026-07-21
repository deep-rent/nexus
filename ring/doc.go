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

// Package ring provides a generic, lock-free ring buffer designed for
// high-throughput concurrent queues.
//
// It relies on atomic compare-and-swap operations to manage read and write
// positions, completely avoiding mutex bottlenecks during high-load scenarios.
// The buffer's capacity is strictly enforced as a power of two, allowing for
// highly efficient bitwise operations when calculating array indices.
//
// # Usage
//
// To use the ring buffer, initialize it with a size and a overflow [Policy],
// then use Push and Pop for concurrent data exchange.
//
// Example:
//
//	rb := ring.New[int](64, ring.DropOldest)
//
//	// Add an item to the queue
//	rb.Push(42)
//
//	// Retrieve the item
//	if val, ok := rb.Pop(); ok {
//		fmt.Println(val) // Output: 42
//	}
package ring
