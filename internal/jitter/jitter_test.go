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

package jitter_test

import (
	"testing"
	"time"

	"github.com/deep-rent/nexus/internal/jitter"
)

type mockRand struct {
	val float64
}

func (m mockRand) Float64() float64 {
	return m.val
}

func TestNew(t *testing.T) {
	t.Parallel()

	j1 := jitter.New(0.5, nil)
	if j1 == nil {
		t.Fatal("jitter.New(0.5, nil) = nil; want non-nil")
	}

	j2 := jitter.New(0.5, mockRand{val: 0.1})
	if j2 == nil {
		t.Fatal("jitter.New(0.5, mockRand) = nil; want non-nil")
	}
}

func TestJitter_Apply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    float64
		rand float64
		give time.Duration
		want time.Duration
	}{
		{"no jitter rand 0", 0.5, 0.0, 100 * time.Second, 100 * time.Second},
		{"half jitter rand 1", 0.5, 1.0, 100 * time.Second, 50 * time.Second},
		{"small jitter rand 1", 0.1, 1.0, 100 * time.Second, 90 * time.Second},
		{"mid jitter", 0.5, 0.5, 100 * time.Second, 75 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			j := jitter.New(tt.p, mockRand{val: tt.rand})
			if got := j.Apply(tt.give); got != tt.want {
				t.Errorf("Apply(%v) = %v; want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestJitter_Floor(t *testing.T) {
	t.Parallel()

	j := jitter.New(0.5, nil)

	tests := []struct {
		name string
		give time.Duration
		f    float64
		want time.Duration
	}{
		{"zero factor", 100 * time.Second, 0.0, 100 * time.Second},
		{"full factor", 100 * time.Second, 1.0, 50 * time.Second},
		{"half factor", 100 * time.Second, 0.5, 75 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := j.Floor(tt.give, tt.f); got != tt.want {
				t.Errorf("Floor(%v, %f) = %v; want %v", tt.give, tt.f, got, tt.want)
			}
		})
	}
}

func TestJitter_Apply_RealRand(t *testing.T) {
	t.Parallel()

	p := 0.1
	j := jitter.New(p, nil)
	d := 100 * time.Millisecond
	min := time.Duration(float64(d) * (1 - p))

	for range 100 {
		got := j.Apply(d)
		if got > d {
			t.Errorf("Apply(%v) = %v; want <= %v", d, got, d)
		}
		if got < min {
			t.Errorf("Apply(%v) = %v; want >= %v", d, got, min)
		}
	}
}
