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

package metrics_test

import (
	"encoding/json/v2"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sys/metrics"
)

func TestRegistry_ReturnsSameInstrument(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()

	a := reg.Counter("hits_total", metrics.T("route", "/a"))
	b := reg.Counter("hits_total", metrics.T("route", "/a"))
	if a != b {
		t.Error("same name and tags: got distinct instruments")
	}

	c := reg.Counter("hits_total", metrics.T("route", "/b"))
	if a == c {
		t.Error("different tags: got the same instrument")
	}
}

func TestRegistry_TagOrderIrrelevant(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()

	a := reg.Counter("hits_total",
		metrics.T("method", "GET"), metrics.T("route", "/a"))
	b := reg.Counter("hits_total",
		metrics.T("route", "/a"), metrics.T("method", "GET"))
	if a != b {
		t.Error("tag order changed identity")
	}
}

func TestRegistry_PanicsOnKindMismatch(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	reg.Counter("size")

	defer func() {
		if recover() == nil {
			t.Error("should have panicked on kind mismatch")
		}
	}()
	reg.Gauge("size")
}

func TestCounter(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	c := reg.Counter("jobs_total")

	c.Inc()
	c.Add(4)

	if got := c.Value(); got != 5 {
		t.Errorf("value: got %d; want 5", got)
	}
}

func TestGauge(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	g := reg.Gauge("pool_size")

	g.Set(10)
	g.Add(2.5)
	g.Dec()

	if got := g.Value(); got != 11.5 {
		t.Errorf("value: got %v; want 11.5", got)
	}
}

func TestHistogram(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	h := reg.Histogram("latency_seconds", []float64{0.1, 1, 10})

	for _, v := range []float64{0.05, 0.1, 0.5, 5, 100} {
		h.Observe(v)
	}

	if got := h.Count(); got != 5 {
		t.Errorf("count: got %d; want 5", got)
	}
	if got, want := h.Sum(), 105.65; math.Abs(got-want) > 1e-9 {
		t.Errorf("sum: got %v; want %v", got, want)
	}

	snap := reg.Snapshot()
	if len(snap.Metrics) != 1 {
		t.Fatalf("metrics: got %d; want 1", len(snap.Metrics))
	}

	// Bounds 0.1, 1, 10 accumulate 2, 3, 4: buckets are cumulative and
	// inclusive of their bound. The observation above the highest bound
	// shows up only in the total count.
	buckets := snap.Metrics[0].Buckets
	want := []uint64{2, 3, 4}
	if len(buckets) != len(want) {
		t.Fatalf("buckets: got %d; want %d", len(buckets), len(want))
	}
	for i, w := range want {
		if buckets[i].Count != w {
			t.Errorf("bucket %d: got %d; want %d", i, buckets[i].Count, w)
		}
	}
	last := buckets[len(buckets)-1]
	if overflow := snap.Metrics[0].Count - last.Count; overflow != 1 {
		t.Errorf("overflow: got %d; want 1", overflow)
	}
}

func TestTimer(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	tm := reg.Timer("job_duration_seconds")

	tm.Observe(250 * time.Millisecond)
	tm.Observe(3 * time.Second)

	if got := tm.Count(); got != 2 {
		t.Errorf("count: got %d; want 2", got)
	}
	if got, want := tm.Sum(), 3.25; math.Abs(got-want) > 1e-9 {
		t.Errorf("sum: got %v; want %v", got, want)
	}

	snap := reg.Snapshot()
	if got := snap.Metrics[0].Kind; got != metrics.KindTimer {
		t.Errorf("kind: got %v; want %v", got, metrics.KindTimer)
	}
	if snap.Metrics[0].Rates == nil {
		t.Error("rates: got nil; want present")
	}
}

func TestMeter_CountsEvents(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	m := reg.Meter("events")

	m.Mark(3)
	m.Mark(2)

	if got := m.Count(); got != 5 {
		t.Errorf("count: got %d; want 5", got)
	}
	if got := m.Rates().Mean; got <= 0 {
		t.Errorf("mean rate: got %v; want > 0", got)
	}
}

func TestRegistry_ConcurrentUse(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				reg.Counter("shared_total").Inc()
				reg.Histogram("shared_seconds", nil).Observe(0.1)
			}
		})
	}
	wg.Wait()

	if got := reg.Counter("shared_total").Value(); got != 8000 {
		t.Errorf("count: got %d; want 8000", got)
	}
	if got := reg.Histogram("shared_seconds", nil).Count(); got != 8000 {
		t.Errorf("observations: got %d; want 8000", got)
	}
}

func TestSnapshot_Deterministic(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	reg.Counter("b_total")
	reg.Counter("a_total", metrics.T("x", "2"))
	reg.Counter("a_total", metrics.T("x", "1"))

	snap := reg.Snapshot()
	var names []string
	for _, s := range snap.Metrics {
		names = append(names, s.Name+"|"+s.Tags["x"])
	}
	want := "a_total|1,a_total|2,b_total|"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("order: got %q; want %q", got, want)
	}
}

func TestHandler(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	reg.Counter("requests_total", metrics.T("route", "/users")).Add(7)
	reg.Histogram("latency_seconds", nil).Observe(0.02)

	srv := httptest.NewServer(reg.Handler())
	defer srv.Close()

	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d; want %d", res.StatusCode, http.StatusOK)
	}
	if got := res.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type: got %q; want %q", got, "application/json")
	}

	// The payload round-trips back into a Snapshot.
	var snap metrics.Snapshot
	if err := json.UnmarshalRead(res.Body, &snap); err != nil {
		t.Fatalf("decoding snapshot: %v", err)
	}

	if len(snap.Metrics) != 2 {
		t.Fatalf("metrics: got %d; want 2", len(snap.Metrics))
	}

	hist := snap.Metrics[0]
	if hist.Name != "latency_seconds" {
		t.Fatalf("name: got %q; want %q", hist.Name, "latency_seconds")
	}
	if got := len(hist.Buckets); got != len(metrics.DefaultDurationBuckets) {
		t.Errorf(
			"buckets: got %d; want %d",
			got, len(metrics.DefaultDurationBuckets),
		)
	}

	counter := snap.Metrics[1]
	if counter.Value != 7 {
		t.Errorf("counter: got %v; want 7", counter.Value)
	}
	if got := counter.Tags["route"]; got != "/users" {
		t.Errorf("tag: got %q; want %q", got, "/users")
	}
}
