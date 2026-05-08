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

package backoff_test

import (
	"math"
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/internal/jitter"
)

type mockRand struct{ val float64 }

func (m *mockRand) Float64() float64 { return m.val }

var _ jitter.Rand = (*mockRand)(nil)

func TestBackoffConstant(t *testing.T) {
	t.Parallel()
	unit := time.Millisecond
	type test struct {
		name  string
		delay time.Duration
		want  time.Duration
	}
	tests := []test{
		{
			name:  "positive delay",
			delay: 100 * unit,
			want:  100 * unit,
		},
		{
			name:  "zero delay",
			delay: 0,
			want:  0,
		},
		{
			name:  "negative delay becomes zero",
			delay: -100 * unit,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := backoff.Constant(tt.delay)

			if got := s.MinDelay(); got != tt.want {
				t.Errorf("MinDelay() = %v; want %v", got, tt.want)
			}
			if got := s.MaxDelay(); got != tt.want {
				t.Errorf("MaxDelay() = %v; want %v", got, tt.want)
			}

			if got := s.Next(); got != tt.want {
				t.Errorf("Next() 1st call = %v; want %v", got, tt.want)
			}
			if got := s.Next(); got != tt.want {
				t.Errorf("Next() 2nd call = %v; want %v", got, tt.want)
			}

			s.Done()
			if got := s.Next(); got != tt.want {
				t.Errorf("Next() after Done() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestBackoffNew(t *testing.T) {
	t.Parallel()
	unit := time.Millisecond
	type test struct {
		name    string
		opts    []backoff.Option
		seq     []time.Duration
		wantMin time.Duration
		wantMax time.Duration
	}
	tests := []test{
		{
			name: "linear",
			opts: []backoff.Option{
				backoff.WithMinDelay(100 * unit),
				backoff.WithMaxDelay(500 * unit),
				backoff.WithGrowthFactor(1.0),
				backoff.WithJitterAmount(0),
			},
			seq: []time.Duration{
				100 * unit,
				200 * unit,
				300 * unit,
				400 * unit,
				500 * unit,
				500 * unit,
			},
			wantMin: 100 * unit,
			wantMax: 500 * unit,
		},
		{
			name: "exponential no jitter",
			opts: []backoff.Option{
				backoff.WithMinDelay(100 * unit),
				backoff.WithMaxDelay(1000 * unit),
				backoff.WithGrowthFactor(2.0),
				backoff.WithJitterAmount(0),
			},
			seq: []time.Duration{
				200 * unit,
				400 * unit,
				800 * unit,
				1000 * unit,
			},
			wantMin: 100 * unit,
			wantMax: 1000 * unit,
		},
		{
			name: "constant from min gte max",
			opts: []backoff.Option{
				backoff.WithMinDelay(500 * unit),
				backoff.WithMaxDelay(400 * unit),
			},
			seq: []time.Duration{
				400 * unit,
				400 * unit,
			},
			wantMin: 400 * unit,
			wantMax: 400 * unit,
		},
		{
			name: "exponential with jitter",
			opts: []backoff.Option{
				backoff.WithMinDelay(100 * unit),
				backoff.WithMaxDelay(1000 * unit),
				backoff.WithGrowthFactor(2.0),
				backoff.WithJitterAmount(0.5),
				backoff.WithRand(&mockRand{val: 0.5}),
			},
			seq: []time.Duration{
				150 * unit,
				300 * unit,
				600 * unit,
			},
			wantMin: 50 * unit,
			wantMax: 1000 * unit,
		},
		{
			name: "negative delay options capped at zero",
			opts: []backoff.Option{
				backoff.WithMinDelay(-1 * time.Second),
				backoff.WithMaxDelay(-1 * time.Minute),
			},
			wantMin: 0,
			wantMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := backoff.New(tt.opts...)

			if got, want := s.MinDelay(),
				tt.wantMin; math.Abs(float64(got-want)) > float64(unit) {
				t.Errorf("MinDelay() = %v; want %v (delta %v)", got, want, unit)
			}

			if got, want := s.MaxDelay(),
				tt.wantMax; math.Abs(float64(got-want)) > float64(unit) {
				t.Errorf("MaxDelay() = %v; want %v (delta %v)", got, want, unit)
			}

			if tt.seq != nil {
				for i, want := range tt.seq {
					got := s.Next()
					if math.Abs(float64(got-want)) > float64(unit) {
						t.Errorf(
							"Next() sequence index %d = %v; want %v (delta %v)",
							i, got, want, unit,
						)
					}
				}
				s.Done()
				got := s.Next()
				if math.Abs(float64(got-tt.seq[0])) > float64(unit) {
					t.Errorf(
						"Next() after Done() = %v; want %v (delta %v)",
						got, tt.seq[0], unit,
					)
				}
			}
		})
	}
}
