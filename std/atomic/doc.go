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

// Package atomic complements [sync/atomic] with floating-point types.
//
// [Float32] and [Float64] mirror the API of the integer types in
// [sync/atomic]: Load, Store, Swap, Add, and CompareAndSwap. Values are
// stored as their IEEE 754 bit patterns in an atomic integer, so all
// operations are lock-free; Add retries with a compare-and-swap loop.
//
// # Usage
//
// The zero value is ready for use and holds 0:
//
//	var f atomic.Float64
//	f.Add(2.5)
//	v := f.Load() // 2.5
//
// # Caveats
//
// CompareAndSwap operates on bit patterns rather than floating-point
// equality. Consequently, a value of NaN can be swapped out only by passing
// the identical NaN bit pattern, and +0 does not match -0 even though they
// compare equal as floats.
package atomic
