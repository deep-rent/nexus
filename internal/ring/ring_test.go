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

package ring_test

import (
	"testing"

	"github.com/deep-rent/nexus/internal/ring"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tcs := []struct {
		name string
		size int
		exp  int
	}{
		{"neg", -1, 2},
		{"zero", 0, 2},
		{"one", 1, 2},
		{"two", 2, 2},
		{"three", 3, 4},
		{"four", 4, 4},
		{"five", 5, 8},
		{"large", 1000, 1024},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b := ring.New[int](tc.size, ring.DropNewest)
			c := 0
			for b.Push(c) {
				c++
			}
			assert.Equal(t, tc.exp, c)
		})
	}
}

func TestPushPop(t *testing.T) {
	b := ring.New[string](4, ring.Block)

	_, ok := b.Pop()
	assert.False(t, ok)

	assert.True(t, b.Push("a"))
	assert.True(t, b.Push("b"))

	v, ok := b.Pop()
	require.True(t, ok)
	assert.Equal(t, "a", v)

	v, ok = b.Pop()
	require.True(t, ok)
	assert.Equal(t, "b", v)

	_, ok = b.Pop()
	assert.False(t, ok)
}

func TestDropNewest(t *testing.T) {
	b := ring.New[int](4, ring.DropNewest)

	for i := 0; i < 4; i++ {
		assert.True(t, b.Push(i))
	}

	assert.False(t, b.Push(4))

	v, ok := b.Pop()
	require.True(t, ok)
	assert.Equal(t, 0, v)
}

func TestDropOldest(t *testing.T) {
	b := ring.New[int](4, ring.DropOldest)

	for i := 0; i < 6; i++ {
		b.Push(i)
	}

	v, ok := b.Pop()
	require.True(t, ok)
	assert.Equal(t, 2, v)

	v, ok = b.Pop()
	require.True(t, ok)
	assert.Equal(t, 3, v)
}
