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

package rotor_test

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deep-rent/nexus/std/rotor"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("panics on empty slice", func(t *testing.T) {
		t.Parallel()
		want := "items slice must not be empty"

		checkPanic := func(t *testing.T, fn func()) {
			t.Helper()
			defer func() {
				r := recover()
				if r == nil {
					t.Errorf("should have panicked with %q", want)
				}
				if r != want {
					t.Errorf("panic value: got %v; want %q", r, want)
				}
			}()
			fn()
		}

		checkPanic(t, func() { rotor.New(rotor.Sequential, []string{}) })
		checkPanic(t, func() { rotor.New(rotor.Sequential, []int{}) })
	})

	t.Run("succeeds with non-empty slice", func(t *testing.T) {
		t.Parallel()
		items := []string{"a", "b", "c"}
		r := rotor.New(rotor.Sequential, items)

		if r == nil {
			t.Fatal("rotor should not be nil")
		}

		expected := []string{"a", "b", "c", "a"}
		for i, want := range expected {
			if got := r.Next(); got != want {
				t.Errorf("on call %d: got %q; want %q", i+1, got, want)
			}
		}
	})

	t.Run("succeeds with single item", func(t *testing.T) {
		t.Parallel()
		items := []string{"a"}
		r := rotor.New(rotor.Sequential, items)

		for range 2 {
			if got, want := r.Next(), "a"; got != want {
				t.Errorf("got %q; want %q", got, want)
			}
		}
	})
}

func TestNew_Copy(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c"}
	r := rotor.New(rotor.Sequential, items)
	items[0] = "Z"

	if got, want := r.Next(), "a"; got != want {
		t.Errorf("after external slice modification: got %q; want %q",
			got, want)
	}
}

func TestRotor_Next_Sequential(t *testing.T) {
	t.Parallel()

	t.Run("string slice", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			give []string
			want []string
		}{
			{
				name: "multiple items",
				give: []string{"1st", "2nd", "3rd"},
				want: []string{"1st", "2nd", "3rd", "1st"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				r := rotor.New(rotor.Sequential, tt.give)
				for i, want := range tt.want {
					if got := r.Next(); got != want {
						t.Errorf("on call %d: got %q; want %q", i+1, got, want)
					}
				}
			})
		}
	})

	t.Run("int slice", func(t *testing.T) {
		t.Parallel()
		items := []int{1, 2}
		r := rotor.New(rotor.Sequential, items)

		sequence := []int{1, 2, 1, 2}
		for i, want := range sequence {
			if got := r.Next(); got != want {
				t.Errorf("on call %d: got %d; want %d", i+1, got, want)
			}
		}
	})

	t.Run("single item slice", func(t *testing.T) {
		t.Parallel()
		items := []bool{true}
		r := rotor.New(rotor.Sequential, items)

		for range 3 {
			if got, want := r.Next(), true; got != want {
				t.Errorf("got %v; want %v", got, want)
			}
		}
	})
}

func TestRotor_Next_Concurrent(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c"}
	r := rotor.New(rotor.Sequential, items)

	const (
		concurrency = 50
		calls       = 100
	)
	exp := uint64(concurrency * calls)

	var countA, countB, countC, countD atomic.Uint64
	var wg sync.WaitGroup

	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			for range calls {
				switch item := r.Next(); item {
				case "a":
					countA.Add(1)
				case "b":
					countB.Add(1)
				case "c":
					countC.Add(1)
				default:
					countD.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if got := countD.Load(); got != 0 {
		t.Errorf("got %d unexpected items; want 0", got)
	}

	a, b, c := countA.Load(), countB.Load(), countC.Load()
	if got, want := a+b+c, exp; got != want {
		t.Errorf("total calls: got %d; want %d", got, want)
	}

	avg := float64(exp) / float64(len(items))
	tol := avg * 0.1 // 10% tolerance for distribution check

	counts := map[string]uint64{"a": a, "b": b, "c": c}
	for label, got := range counts {
		if diff := math.Abs(float64(got) - avg); diff > tol {
			t.Errorf("for %q: got count %d; want %f (tolerance %f)",
				label, got, avg, tol)
		}
	}
}
