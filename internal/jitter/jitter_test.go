package jitter_test

import (
	"testing"
	"time"

	"github.com/deep-rent/nexus/internal/jitter"
	"github.com/stretchr/testify/assert"
)

type mockRand struct {
	val float64
}

func (m mockRand) Float64() float64 {
	return m.val
}

func TestNew(t *testing.T) {
	j1 := jitter.New(0.5, nil)
	assert.NotNil(t, j1)

	j2 := jitter.New(0.5, mockRand{val: 0.1})
	assert.NotNil(t, j2)
}

func TestApply(t *testing.T) {
	tests := []struct {
		name     string
		p        float64
		rand     float64
		input    time.Duration
		expected time.Duration
	}{
		{"no_jitter_rand_0", 0.5, 0.0, 100 * time.Second, 100 * time.Second},
		{"half_jitter_rand_1", 0.5, 1.0, 100 * time.Second, 50 * time.Second},
		{"small_jitter_rand_1", 0.1, 1.0, 100 * time.Second, 90 * time.Second},
		{"mid_jitter", 0.5, 0.5, 100 * time.Second, 75 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := jitter.New(tt.p, mockRand{val: tt.rand})
			got := j.Apply(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFloor(t *testing.T) {
	j := jitter.New(0.5, nil) // p = 0.5

	tests := []struct {
		d        time.Duration
		f        float64
		expected time.Duration
	}{
		{100 * time.Second, 0.0, 100 * time.Second},
		{100 * time.Second, 1.0, 50 * time.Second},
		{100 * time.Second, 0.5, 75 * time.Second},
	}

	for _, tt := range tests {
		got := j.Floor(tt.d, tt.f)
		assert.Equal(t, tt.expected, got)
	}
}

// func TestRealRand(t *testing.T) {
// 	j := jitter.New(0.1, nil)
// 	d := 100 * time.Millisecond

// 	for range 100 {
// 		got := j.Apply(d)
// 		assert.LessOrEqual(t, got, d)
// 		assert.GreaterOrEqual(t, got, time.Duration(float64(d)*0.9))
// 	}
// }
