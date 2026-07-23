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

package atomic

import (
	"math"
	"sync/atomic"
)

// Float32 is an atomic float32. The zero value holds 0.
type Float32 struct {
	bits atomic.Uint32
}

// Load atomically returns the value stored in f.
func (f *Float32) Load() float32 {
	return math.Float32frombits(f.bits.Load())
}

// Store atomically stores v into f.
func (f *Float32) Store(v float32) {
	f.bits.Store(math.Float32bits(v))
}

// Swap atomically stores v into f and returns the previous value.
func (f *Float32) Swap(v float32) (old float32) {
	return math.Float32frombits(f.bits.Swap(math.Float32bits(v)))
}

// Add atomically adds delta to f and returns the new value. The addition is
// performed with a compare-and-swap loop.
func (f *Float32) Add(delta float32) (new float32) {
	for {
		old := f.bits.Load()
		new := math.Float32frombits(old) + delta
		if f.bits.CompareAndSwap(old, math.Float32bits(new)) {
			return new
		}
	}
}

// CompareAndSwap executes the compare-and-swap operation for f. The
// comparison is on bit patterns, not floating-point equality; see the
// package documentation for the resulting NaN and signed-zero caveats.
func (f *Float32) CompareAndSwap(old, new float32) (swapped bool) {
	return f.bits.CompareAndSwap(math.Float32bits(old), math.Float32bits(new))
}

// Float64 is an atomic float64. The zero value holds 0.
type Float64 struct {
	bits atomic.Uint64
}

// Load atomically returns the value stored in f.
func (f *Float64) Load() float64 {
	return math.Float64frombits(f.bits.Load())
}

// Store atomically stores v into f.
func (f *Float64) Store(v float64) {
	f.bits.Store(math.Float64bits(v))
}

// Swap atomically stores v into f and returns the previous value.
func (f *Float64) Swap(v float64) (old float64) {
	return math.Float64frombits(f.bits.Swap(math.Float64bits(v)))
}

// Add atomically adds delta to f and returns the new value. The addition is
// performed with a compare-and-swap loop.
func (f *Float64) Add(delta float64) (new float64) {
	for {
		old := f.bits.Load()
		new := math.Float64frombits(old) + delta
		if f.bits.CompareAndSwap(old, math.Float64bits(new)) {
			return new
		}
	}
}

// CompareAndSwap executes the compare-and-swap operation for f. The
// comparison is on bit patterns, not floating-point equality; see the
// package documentation for the resulting NaN and signed-zero caveats.
func (f *Float64) CompareAndSwap(old, new float64) (swapped bool) {
	return f.bits.CompareAndSwap(math.Float64bits(old), math.Float64bits(new))
}
