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
)

func TestNew(t *testing.T) {
	t.Parallel()

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := ring.New[int](tt.size, ring.DropNewest)
			c := 0
			for b.Push(c) {
				c++
			}
			if got, want := c, tt.want; got != want {
				t.Errorf("New(%d) final count = %d; want %d", tt.size, got, want)
			}
		})
	}
}

func TestRing_Push_Pop(t *testing.T) {
	t.Parallel()

	b := ring.New[string](4, ring.Block)

	if _, ok := b.Pop(); ok {
		t.Errorf("Pop() on empty ring = _, true; want _, false")
	}

	if !b.Push("a") {
		t.Errorf("Push(%q) = false; want true", "a")
	}
	if !b.Push("b") {
		t.Errorf("Push(%q) = false; want true", "b")
	}

	v1, ok1 := b.Pop()
	if !ok1 {
		t.Fatalf("Pop() #1 = _, false; want _, true")
	}
	if got, want := v1, "a"; got != want {
		t.Errorf("Pop() #1 = %q; want %q", got, want)
	}

	v2, ok2 := b.Pop()
	if !ok2 {
		t.Fatalf("Pop() #2 = _, false; want _, true")
	}
	if got, want := v2, "b"; got != want {
		t.Errorf("Pop() #2 = %q; want %q", got, want)
	}

	if _, ok := b.Pop(); ok {
		t.Errorf("Pop() after drain = _, true; want _, false")
	}
}

func TestRing_Push_DropNewest(t *testing.T) {
	t.Parallel()

	b := ring.New[int](4, ring.DropNewest)

	for i := range 4 {
		if !b.Push(i) {
			t.Errorf("Push(%d) = false; want true", i)
		}
	}

	if b.Push(4) {
		t.Errorf("Push(4) to full DropNewest ring = true; want false")
	}

	v, ok := b.Pop()
	if !ok {
		t.Fatalf("Pop() = _, false; want _, true")
	}
	if got, want := v, 0; got != want {
		t.Errorf("Pop() = %d; want %d", got, want)
	}
}

func TestRing_Push_DropOldest(t *testing.T) {
	t.Parallel()

	b := ring.New[int](4, ring.DropOldest)

	for i := range 6 {
		b.Push(i)
	}

	v1, ok1 := b.Pop()
	if !ok1 {
		t.Fatalf("Pop() #1 = _, false; want _, true")
	}
	if got, want := v1, 2; got != want {
		t.Errorf("Pop() #1 = %d; want %d", got, want)
	}

	v2, ok2 := b.Pop()
	if !ok2 {
		t.Fatalf("Pop() #2 = _, false; want _, true")
	}
	if got, want := v2, 3; got != want {
		t.Errorf("Pop() #2 = %d; want %d", got, want)
	}
}

func TestRing_ConcurrentMPSC(t *testing.T) {
	t.Parallel()

	b := ring.New[int](1024, ring.Block)
	var wg sync.WaitGroup

	p := 4
	i := 10000
	total := p * i

	wg.Add(p)
	for range p {
		go func() {
			defer wg.Done()
			for range i {
				for !b.Push(1) {
					// Busy wait simulation
				}
			}
		}()
	}

	var count int
	done := make(chan struct{})

	go func() {
		for count < total {
			if _, ok := b.Pop(); ok {
				count++
			}
		}
		close(done)
	}()

	wg.Wait()
	<-done

	if got, want := count, total; got != want {
		t.Errorf("count = %d; want %d", got, want)
	}
}
