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
	"testing"

	"github.com/deep-rent/nexus/internal/buffer"
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

func TestPool_GetPut(t *testing.T) {
	t.Parallel()

	min, max := 64, 1024
	p := buffer.NewPool(min, max)

	b1 := p.Get()
	if got, want := cap(b1), min; got != want {
		t.Fatalf("got capacity %d; want %d", got, want)
	}

	p.Put(b1)

	b2 := p.Get()
	if &b1[0] != &b2[0] {
		t.Error("should have returned the recycled buffer")
	}
}

func TestPool_Put_DiscardOversized(t *testing.T) {
	t.Parallel()

	min, max := 64, 128
	p := buffer.NewPool(min, max)

	b1 := p.Get()
	b1[0] = 10
	p.Put(b1)

	// Buffer exceeds max capacity
	bO := make([]byte, min, max+1)
	bO[0] = 42
	p.Put(bO)

	bR := p.Get()
	if &b1[0] != &bR[0] {
		t.Error("should have returned the recycled buffer b1")
	}
	if got, want := int(bR[0]), 10; got != want {
		t.Errorf("recycled b1: got %d; want %d", got, want)
	}

	// Buffer at max capacity
	bM := make([]byte, min, max)
	bM[0] = 99
	p.Put(bM)

	bK := p.Get()
	if &bM[0] != &bK[0] {
		t.Error("should have returned the recycled buffer bM")
	}
	if got, want := int(bK[0]), 99; got != want {
		t.Errorf("recycled bM: got %d; want %d", got, want)
	}
}
