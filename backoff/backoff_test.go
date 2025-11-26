package backoff_test

import (
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/internal/jitter"
	"github.com/stretchr/testify/assert"
)

type mockRand struct{ val float64 }

func (m *mockRand) Float64() float64 { return m.val }

var _ jitter.Rand = (*mockRand)(nil)

func TestConstant(t *testing.T) {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := backoff.Constant(tc.delay)
			assert.Equal(t, tc.want, s.MinDelay(), "MinDelay")
			assert.Equal(t, tc.want, s.MaxDelay(), "MaxDelay")
			assert.Equal(t, tc.want, s.Next(), "1st call to Next()")
			assert.Equal(t, tc.want, s.Next(), "2nd call to Next()")

			s.Done()
			assert.Equal(t, tc.want, s.Next(), "Next() after Done()")
		})
	}
}

func TestNew(t *testing.T) {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := backoff.New(tc.opts...)
			assert.InDelta(t, tc.wantMin, s.MinDelay(), float64(unit))
			assert.InDelta(t, tc.wantMax, s.MaxDelay(), float64(unit))

			if tc.seq != nil {
				for i, want := range tc.seq {
					got := s.Next()
					assert.InDeltaf(t, want, got, float64(unit), "sequence index %d", i)
				}

				s.Done()
				got := s.Next()
				assert.InDeltaf(t, tc.seq[0], got, float64(unit), "after Done()")
			}
		})
	}
}
