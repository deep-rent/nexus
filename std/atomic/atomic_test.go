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

package atomic_test

import (
	"math"
	"sync"
	"testing"

	"github.com/deep-rent/nexus/std/atomic"
)

func TestFloat32_LoadStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    float32
	}{
		{"zero", 0},
		{"positive", 2.5},
		{"negative", -1.75},
		{"tiny", math.SmallestNonzeroFloat32},
		{"max", math.MaxFloat32},
		{"inf", float32(math.Inf(1))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var f atomic.Float32
			f.Store(tt.v)
			if got, want := f.Load(), tt.v; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestFloat32_Zero(t *testing.T) {
	t.Parallel()

	var f atomic.Float32
	if got := f.Load(); got != 0 {
		t.Errorf("got %v; want 0", got)
	}
}

func TestFloat32_Swap(t *testing.T) {
	t.Parallel()

	var f atomic.Float32
	f.Store(1.5)
	if got, want := f.Swap(-2.5), float32(1.5); got != want {
		t.Errorf("got old %v; want %v", got, want)
	}
	if got, want := f.Load(), float32(-2.5); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat32_Add(t *testing.T) {
	t.Parallel()

	var f atomic.Float32
	if got, want := f.Add(1.5), float32(1.5); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
	if got, want := f.Add(-0.5), float32(1); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
	if got, want := f.Load(), float32(1); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat32_CompareAndSwap(t *testing.T) {
	t.Parallel()

	var f atomic.Float32
	f.Store(1)
	if f.CompareAndSwap(2, 3) {
		t.Error("swapped with mismatched old value")
	}
	if !f.CompareAndSwap(1, 3) {
		t.Error("failed to swap with matching old value")
	}
	if got, want := f.Load(), float32(3); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat64_LoadStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    float64
	}{
		{"zero", 0},
		{"positive", 2.5},
		{"negative", -1.75},
		{"tiny", math.SmallestNonzeroFloat64},
		{"max", math.MaxFloat64},
		{"inf", math.Inf(-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var f atomic.Float64
			f.Store(tt.v)
			if got, want := f.Load(), tt.v; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		})
	}
}

func TestFloat64_Zero(t *testing.T) {
	t.Parallel()

	var f atomic.Float64
	if got := f.Load(); got != 0 {
		t.Errorf("got %v; want 0", got)
	}
}

func TestFloat64_Swap(t *testing.T) {
	t.Parallel()

	var f atomic.Float64
	f.Store(1.5)
	if got, want := f.Swap(-2.5), 1.5; got != want {
		t.Errorf("got old %v; want %v", got, want)
	}
	if got, want := f.Load(), -2.5; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat64_Add(t *testing.T) {
	t.Parallel()

	var f atomic.Float64
	if got, want := f.Add(1.5), 1.5; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
	if got, want := f.Add(-0.5), 1.0; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
	if got, want := f.Load(), 1.0; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat64_CompareAndSwap(t *testing.T) {
	t.Parallel()

	var f atomic.Float64
	f.Store(1)
	if f.CompareAndSwap(2, 3) {
		t.Error("swapped with mismatched old value")
	}
	if !f.CompareAndSwap(1, 3) {
		t.Error("failed to swap with matching old value")
	}
	if got, want := f.Load(), 3.0; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat64_NaN(t *testing.T) {
	t.Parallel()

	var f atomic.Float64
	f.Store(math.NaN())
	if got := f.Load(); !math.IsNaN(got) {
		t.Errorf("got %v; want NaN", got)
	}
	// CAS compares bit patterns, so the identical NaN swaps out.
	if !f.CompareAndSwap(math.NaN(), 1) {
		t.Error("failed to swap identical NaN bit pattern")
	}
	if got, want := f.Load(), 1.0; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat64_Add_Concurrent(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 8
		iterations = 1000
	)

	var f atomic.Float64
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				f.Add(1)
			}
		}()
	}
	wg.Wait()

	if got, want := f.Load(), float64(goroutines*iterations); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestFloat32_Add_Concurrent(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 8
		iterations = 1000
	)

	var f atomic.Float32
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				f.Add(1)
			}
		}()
	}
	wg.Wait()

	if got, want := f.Load(), float32(goroutines*iterations); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}
