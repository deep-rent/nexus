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

package buffer_test

import (
	"sync"
	"testing"

	"github.com/deep-rent/nexus/net/proxy/buffer"
)

func TestNewPool_PanicOnInvalidSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		min  int
		max  int
	}{
		{"min zero", 0, 1024},
		{"max zero", 1024, 0},
		{"min negative", -1, 1024},
		{"max negative", 1024, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Error("should have panicked")
				}
			}()
			buffer.NewPool(tt.min, tt.max)
		})
	}
}

func TestNewPool_SizeClamping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		min  int
		max  int
		want int
	}{
		{"min larger than max", 100, 50, 50},
		{"min smaller than max", 50, 100, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := buffer.NewPool(tt.min, tt.max)
			if got := cap(p.Get()); got != tt.want {
				t.Errorf("got capacity %d; want %d", got, tt.want)
			}
		})
	}
}

func TestPool_GetReturnsUsableBuffer(t *testing.T) {
	t.Parallel()

	minSize, maxSize := 64, 1024
	p := buffer.NewPool(minSize, maxSize)

	for range 10 {
		buf := p.Get()

		if got := cap(buf); got < minSize {
			t.Errorf("capacity: got %d; want at least %d", got, minSize)
		}

		// io.CopyBuffer, which is how httputil.ReverseProxy consumes this
		// pool, panics on a zero-length buffer.
		if len(buf) == 0 {
			t.Error("length: got 0; want a writable buffer")
		}

		p.Put(buf)
	}
}

// A caller that re-slices a buffer while using it must not poison the pool
// for whoever gets it next.
func TestPool_PutRestoresLength(t *testing.T) {
	t.Parallel()

	minSize, maxSize := 64, 1024
	p := buffer.NewPool(minSize, maxSize)

	tests := []struct {
		name string
		cut  func([]byte) []byte
	}{
		{"emptied", func(b []byte) []byte { return b[:0] }},
		{"halved", func(b []byte) []byte { return b[:len(b)/2] }},
		{"whole", func(b []byte) []byte { return b }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p.Put(tt.cut(p.Get()))

			// The pool may hand back a fresh buffer instead of the recycled
			// one, so this asserts the invariant, not the identity.
			if got := p.Get(); len(got) == 0 {
				t.Error("length: got 0; want a writable buffer")
			}
		})
	}
}

// A buffer larger than the limit must never come back out of the pool.
func TestPool_PutDiscardsOversized(t *testing.T) {
	t.Parallel()

	minSize, maxSize := 64, 128
	p := buffer.NewPool(minSize, maxSize)

	// Offer far more oversized buffers than the pool could plausibly hold, so
	// that a leaked one would almost certainly resurface below.
	for range 100 {
		p.Put(make([]byte, maxSize+1))
	}

	for range 100 {
		if got := cap(p.Get()); got > maxSize {
			t.Fatalf("capacity: got %d; want at most %d", got, maxSize)
		}
	}
}

// A buffer sitting exactly on the limit is still worth recycling.
func TestPool_PutAcceptsMaxSized(t *testing.T) {
	t.Parallel()

	minSize, maxSize := 64, 128
	p := buffer.NewPool(minSize, maxSize)

	buf := make([]byte, maxSize)
	p.Put(buf)

	if got := p.Get(); len(got) == 0 {
		t.Error("length: got 0; want a writable buffer")
	}
}

func TestPool_Concurrent(t *testing.T) {
	t.Parallel()

	p := buffer.NewPool(64, 1024)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 200 {
				buf := p.Get()
				if len(buf) == 0 {
					t.Error("length: got 0; want a writable buffer")
					return
				}
				buf[0] = 1
				p.Put(buf[:len(buf)/2])
			}
		})
	}
	wg.Wait()
}
