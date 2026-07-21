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

package metrics

import (
	"math"
	"slices"
	"sort"
	"sync/atomic"
	"time"
)

// atomicFloat is a float64 manipulated through atomic bit operations.
type atomicFloat struct {
	bits atomic.Uint64
}

// Load returns the current value.
func (f *atomicFloat) Load() float64 {
	return math.Float64frombits(f.bits.Load())
}

// Store replaces the current value.
func (f *atomicFloat) Store(v float64) {
	f.bits.Store(math.Float64bits(v))
}

// Add adds delta to the current value using a CAS loop.
func (f *atomicFloat) Add(delta float64) {
	for {
		old := f.bits.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if f.bits.CompareAndSwap(old, next) {
			return
		}
	}
}

// Counter is a monotonically increasing count. The zero value is ready for
// use, but counters should be obtained from a [Registry] so they appear in
// snapshots.
type Counter struct {
	count atomic.Uint64
}

// Inc increments the counter by one.
func (c *Counter) Inc() {
	c.count.Add(1)
}

// Add increments the counter by n.
func (c *Counter) Add(n uint64) {
	c.count.Add(n)
}

// Value returns the current count.
func (c *Counter) Value() uint64 {
	return c.count.Load()
}

func (c *Counter) kind() Kind { return KindCounter }

func (c *Counter) sample(s *Sample) {
	s.Value = float64(c.count.Load())
}

// Gauge is a value that can go up and down, such as a queue depth or a pool
// size. The zero value is ready for use, but gauges should be obtained from
// a [Registry] so they appear in snapshots.
type Gauge struct {
	value atomicFloat
}

// Set replaces the current value.
func (g *Gauge) Set(v float64) {
	g.value.Store(v)
}

// Add adds delta to the current value; a negative delta subtracts.
func (g *Gauge) Add(delta float64) {
	g.value.Add(delta)
}

// Inc increments the gauge by one.
func (g *Gauge) Inc() {
	g.value.Add(1)
}

// Dec decrements the gauge by one.
func (g *Gauge) Dec() {
	g.value.Add(-1)
}

// Value returns the current value.
func (g *Gauge) Value() float64 {
	return g.value.Load()
}

func (g *Gauge) kind() Kind { return KindGauge }

func (g *Gauge) sample(s *Sample) {
	s.Value = g.value.Load()
}

// DefaultDurationBuckets are histogram bucket upper bounds suited to request
// and task latencies, in seconds.
var DefaultDurationBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10,
}

// Histogram records the distribution of observations across fixed buckets,
// along with their count and sum. Observations above the highest bound fall
// into an implicit overflow bucket, so quantile estimates are bounded by the
// chosen bucket layout.
type Histogram struct {
	bounds []float64 // sorted upper bounds
	counts []atomic.Uint64
	count  atomic.Uint64
	sum    atomicFloat
}

// newHistogram builds a histogram with the given sorted upper bounds,
// falling back to [DefaultDurationBuckets] when none are given.
func newHistogram(bounds []float64) *Histogram {
	if len(bounds) == 0 {
		bounds = DefaultDurationBuckets
	}
	bounds = slices.Clone(bounds)
	slices.Sort(bounds)
	return &Histogram{
		bounds: bounds,
		counts: make([]atomic.Uint64, len(bounds)+1),
	}
}

// Observe records a single observation.
func (h *Histogram) Observe(v float64) {
	// The last cell is the overflow bucket for values above every bound.
	h.counts[sort.SearchFloat64s(h.bounds, v)].Add(1)
	h.count.Add(1)
	h.sum.Add(v)
}

// Count returns the number of observations recorded.
func (h *Histogram) Count() uint64 {
	return h.count.Load()
}

// Sum returns the sum of all recorded observations.
func (h *Histogram) Sum() float64 {
	return h.sum.Load()
}

func (h *Histogram) kind() Kind { return KindHistogram }

func (h *Histogram) sample(s *Sample) {
	s.Count = h.count.Load()
	s.Sum = h.sum.Load()
	s.Buckets = h.buckets()
}

// buckets renders the cumulative bucket counts, Prometheus-style: each
// bucket counts observations less than or equal to its bound. The overflow
// cell has no bucket of its own — its share is the difference between the
// total count and the last bucket.
func (h *Histogram) buckets() []Bucket {
	buckets := make([]Bucket, len(h.bounds))
	var cum uint64
	for i := range h.bounds {
		cum += h.counts[i].Load()
		buckets[i] = Bucket{Bound: h.bounds[i], Count: cum}
	}
	return buckets
}

// Meter measures the rate of events: a total count together with 1-, 5-, and
// 15-minute exponentially weighted moving averages, in events per second.
//
// Rates advance lazily: the decay owed since the last advance is applied
// when the meter is marked or read, so an idle meter costs nothing.
type Meter struct {
	count     atomic.Uint64 // total marks
	uncounted atomic.Uint64 // marks since the last tick
	started   time.Time     // creation time, for the mean rate

	tick atomic.Int64 // unix nanos of the last rate advance
	r01  atomicFloat
	r05  atomicFloat
	r15  atomicFloat
	warm atomic.Bool // whether the rates have been seeded

	now func() time.Time // clock, replaced in tests
}

// tickInterval is the resolution at which meter rates advance.
const tickInterval = 5 * time.Second

// Decay factors per tick for the moving averages: 1 - e^(-interval/window).
var (
	alpha01 = 1 - math.Exp(-tickInterval.Seconds()/(1*60))
	alpha05 = 1 - math.Exp(-tickInterval.Seconds()/(5*60))
	alpha15 = 1 - math.Exp(-tickInterval.Seconds()/(15*60))
)

// newMeter builds a meter starting now.
func newMeter() *Meter {
	m := &Meter{started: time.Now(), now: time.Now}
	m.tick.Store(m.started.UnixNano())
	return m
}

// Mark records the occurrence of n events.
func (m *Meter) Mark(n uint64) {
	m.advance()
	m.count.Add(n)
	m.uncounted.Add(n)
}

// Count returns the total number of events recorded.
func (m *Meter) Count() uint64 {
	return m.count.Load()
}

// Rates returns the moving average rates in events per second, along with
// the mean rate since the meter was created.
func (m *Meter) Rates() Rates {
	m.advance()
	mean := 0.0
	if elapsed := m.now().Sub(m.started).Seconds(); elapsed > 0 {
		mean = float64(m.count.Load()) / elapsed
	}
	return Rates{
		M01:  m.r01.Load(),
		M05:  m.r05.Load(),
		M15:  m.r15.Load(),
		Mean: mean,
	}
}

// advance applies any decay owed since the last tick. The CAS on the tick
// timestamp elects a single writer per interval; losers simply proceed, at
// worst leaving their marks for the next tick.
func (m *Meter) advance() {
	now := m.now().UnixNano()
	last := m.tick.Load()
	elapsed := now - last
	if elapsed < int64(tickInterval) {
		return
	}

	ticks := elapsed / int64(tickInterval)
	if !m.tick.CompareAndSwap(last, last+ticks*int64(tickInterval)) {
		return // Another goroutine is advancing.
	}

	// The marks accumulated since the last tick all count toward the first
	// elapsed interval; the remaining intervals were idle.
	instant := float64(m.uncounted.Swap(0)) / tickInterval.Seconds()

	if !m.warm.Swap(true) {
		// The first tick seeds the averages with the observed rate.
		m.r01.Store(instant)
		m.r05.Store(instant)
		m.r15.Store(instant)
		ticks--
		instant = 0
	}

	for range ticks {
		m.r01.Store(ewma(m.r01.Load(), instant, alpha01))
		m.r05.Store(ewma(m.r05.Load(), instant, alpha05))
		m.r15.Store(ewma(m.r15.Load(), instant, alpha15))
		instant = 0 // Only the first interval carries the marks.
	}
}

// ewma folds an instant rate into a moving average with the given decay.
func ewma(avg, instant, alpha float64) float64 {
	return avg + alpha*(instant-avg)
}

func (m *Meter) kind() Kind { return KindMeter }

func (m *Meter) sample(s *Sample) {
	rates := m.Rates()
	s.Count = m.count.Load()
	s.Rates = &rates
}

// Timer measures durations: a [Histogram] of seconds combined with a [Meter]
// tracking the event rate.
type Timer struct {
	hist  *Histogram
	meter *Meter
}

// Observe records a completed duration.
func (t *Timer) Observe(d time.Duration) {
	t.hist.Observe(d.Seconds())
	t.meter.Mark(1)
}

// Start begins timing and returns a function that records the elapsed
// duration when called:
//
//	defer timer.Start()()
func (t *Timer) Start() func() {
	start := time.Now()
	return func() {
		t.Observe(time.Since(start))
	}
}

// Count returns the number of durations recorded.
func (t *Timer) Count() uint64 {
	return t.hist.Count()
}

// Sum returns the total of all recorded durations in seconds.
func (t *Timer) Sum() float64 {
	return t.hist.Sum()
}

// Rates returns the moving average rates; see [Meter.Rates].
func (t *Timer) Rates() Rates {
	return t.meter.Rates()
}

func (t *Timer) kind() Kind { return KindTimer }

func (t *Timer) sample(s *Sample) {
	t.hist.sample(s)
	rates := t.meter.Rates()
	s.Rates = &rates
}
