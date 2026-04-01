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
	"sync"
	"testing"

	"github.com/deep-rent/nexus/internal/ring"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		size int
		want int
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := ring.New[int](tc.size, ring.DropNewest)
			c := 0
			for b.Push(c) {
				c++
			}
			assert.Equal(t, tc.want, c)
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

	for i := range 4 {
		assert.True(t, b.Push(i))
	}

	assert.False(t, b.Push(4))

	v, ok := b.Pop()
	require.True(t, ok)
	assert.Equal(t, 0, v)
}

func TestDropOldest(t *testing.T) {
	b := ring.New[int](4, ring.DropOldest)

	for i := range 6 {
		b.Push(i)
	}

	v, ok := b.Pop()
	require.True(t, ok)
	assert.Equal(t, 2, v)

	v, ok = b.Pop()
	require.True(t, ok)
	assert.Equal(t, 3, v)
}

func TestConcurrentMPSC(t *testing.T) {
	b := ring.New[int](1024, ring.Block)
	var wg sync.WaitGroup

	p := 4
	i := 10000
	n := p * i

	wg.Add(p)
	for range p {
		go func() {
			defer wg.Done()
			for range i {
				for !b.Push(1) {
				}
			}
		}()
	}

	var c int
	d := make(chan struct{})

	go func() {
		for c < n {
			if _, ok := b.Pop(); ok {
				c++
			}
		}
		close(d)
	}()

	wg.Wait()
	<-d
	assert.Equal(t, n, c)
}
