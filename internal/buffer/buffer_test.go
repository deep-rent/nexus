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
	"github.com/stretchr/testify/assert"
)

func TestPanicOnInvalidSize(t *testing.T) {
	assert.Panics(t, func() {
		buffer.NewPool(0, 1024)
	})
	assert.Panics(t, func() {
		buffer.NewPool(1024, 0)
	})
	assert.Panics(t, func() {
		buffer.NewPool(-1, 1024)
	})
	assert.Panics(t, func() {
		buffer.NewPool(1024, -1)
	})
}

func TestSizeClamping(t *testing.T) {
	p1 := buffer.NewPool(100, 50)
	assert.Equal(t, 50, cap(p1.Get()))

	p2 := buffer.NewPool(50, 100)
	assert.Equal(t, 50, cap(p2.Get()))
}

func TestGetPut(t *testing.T) {
	min := 64
	max := 1024
	p := buffer.NewPool(min, max)

	b1 := p.Get()
	assert.Equal(t, min, cap(b1))

	p.Put(b1)

	b2 := p.Get()
	assert.True(t, &b1[0] == &b2[0])
}

func TestPutDiscardOversized(t *testing.T) {
	min := 64
	max := 128
	p := buffer.NewPool(min, max)

	b1 := p.Get()
	b1[0] = 10
	p.Put(b1)

	bO := make([]byte, min, max+1)
	bO[0] = 42
	p.Put(bO)

	bR := p.Get()
	assert.True(t, &b1[0] == &bR[0])
	assert.Equal(t, 10, int(bR[0]))

	bM := make([]byte, min, max)
	bM[0] = 99
	p.Put(bM)

	bK := p.Get()
	assert.True(t, &bM[0] == &bK[0])
	assert.Equal(t, 99, int(bK[0]))
}
