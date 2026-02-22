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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deep-rent/nexus/internal/rotor"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("panics on empty slice", func(t *testing.T) {
		assert.PanicsWithValue(t, "rotor: items slice must not be empty", func() {
			rotor.New([]string{})
		}, "New with an empty string slice should panic")

		assert.PanicsWithValue(t, "rotor: items slice must not be empty", func() {
			rotor.New([]int{})
		}, "New with an empty int slice should panic")
	})

	t.Run("succeeds with non-empty slice", func(t *testing.T) {
		items := []string{"a", "b", "c"}

		assert.NotPanics(t, func() {
			r := rotor.New(items)
			assert.NotNil(t, r)
			assert.Equal(t, "a", r.Next())
			assert.Equal(t, "b", r.Next())
			assert.Equal(t, "c", r.Next())
			assert.Equal(t, "a", r.Next())
		})
	})

	t.Run("succeeds with single item", func(t *testing.T) {
		items := []string{"a"}

		assert.NotPanics(t, func() {
			r := rotor.New(items)
			assert.NotNil(t, r)
			assert.Equal(t, "a", r.Next())
			assert.Equal(t, "a", r.Next())
		})
	})
}

func TestNew_Copy(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c"}
	r := rotor.New(items)
	items[0] = "Z"

	assert.Equal(t, "a", r.Next(), "Rotor should make a copy")
	assert.Equal(t, "b", r.Next())
	assert.Equal(t, "c", r.Next())
	assert.Equal(t, "a", r.Next(), "Rotor should wrap around to the original")
}

func TestRotor_Next_Sequential(t *testing.T) {
	t.Parallel()

	t.Run("string slice", func(t *testing.T) {
		items := []string{"1st", "2nd", "3rd"}
		r := rotor.New(items)

		assert.Equal(t, "1st", r.Next())
		assert.Equal(t, "2nd", r.Next())
		assert.Equal(t, "3rd", r.Next())

		assert.Equal(t, "1st", r.Next())
		assert.Equal(t, "2nd", r.Next())
		assert.Equal(t, "3rd", r.Next())
	})

	t.Run("int slice", func(t *testing.T) {
		items := []int{1, 2}
		r := rotor.New(items)

		assert.Equal(t, 1, r.Next())
		assert.Equal(t, 2, r.Next())

		assert.Equal(t, 1, r.Next())
		assert.Equal(t, 2, r.Next())
	})

	t.Run("single item slice", func(t *testing.T) {
		items := []bool{true}
		r := rotor.New(items)

		assert.Equal(t, true, r.Next())
		assert.Equal(t, true, r.Next())
		assert.Equal(t, true, r.Next())
	})
}

func TestRotor_Next_Concurrent(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c"}
	r := rotor.New(items)

	concurrency := 50
	calls := 100
	total := uint64(concurrency * calls)

	var countA, countB, countC, countD atomic.Uint64
	var wg sync.WaitGroup

	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			for j := 0; j < calls; j++ {
				item := r.Next()
				switch item {
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

	assert.Equal(t, uint64(0), countD.Load(), "Received an unexpected item")

	a := countA.Load()
	b := countB.Load()
	c := countC.Load()
	sum := a + b + c

	assert.Equal(t, total, sum, "Total calls do not match expected")
	count := float64(total) / float64(len(items))
	tolerance := count * 0.1

	assert.InDelta(t, count, a, tolerance, "Distribution for 'a' is uneven")
	assert.InDelta(t, count, b, tolerance, "Distribution for 'b' is uneven")
	assert.InDelta(t, count, c, tolerance, "Distribution for 'c' is uneven")
}
