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

package scrape_test

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/sys/metrics/scrape"
)

// endpoint builds a registry pre-loaded by fill and serves its collection
// endpoint.
func endpoint(
	t *testing.T,
	fill func(reg *metrics.Registry),
) *httptest.Server {
	t.Helper()
	reg := metrics.NewRegistry()
	fill(reg)
	srv := httptest.NewServer(reg.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestCollector_MergesTargets(t *testing.T) {
	t.Parallel()

	one := endpoint(t, func(reg *metrics.Registry) {
		reg.Counter("requests_total", metrics.T("route", "/a")).Add(3)
		reg.Gauge("pool_size").Set(4)
	})
	two := endpoint(t, func(reg *metrics.Registry) {
		reg.Counter("requests_total", metrics.T("route", "/a")).Add(5)
		reg.Gauge("pool_size").Set(6)
	})

	c := scrape.New(scrape.WithLogger(log.Discard()))
	c.Add("api-1", one.URL)
	c.Add("api-2", two.URL)
	c.Run(t.Context())

	summary := c.Summary()

	if got := len(summary.Targets); got != 2 {
		t.Fatalf("targets: got %d; want 2", got)
	}
	for _, target := range summary.Targets {
		if !target.Up {
			t.Errorf("target %s: got down; want up", target.Name)
		}
		if target.Error != "" {
			t.Errorf(
				"target %s: unexpected error %q",
				target.Name,
				target.Error,
			)
		}
	}

	// The union carries every sample tagged with its instance.
	if got := len(summary.Metrics); got != 4 {
		t.Fatalf("metrics: got %d; want 4", got)
	}
	instances := make(map[string]int)
	for _, s := range summary.Metrics {
		instances[s.Tags[scrape.InstanceTag]]++
	}
	if instances["api-1"] != 2 || instances["api-2"] != 2 {
		t.Errorf("instance tags: got %v; want 2 each", instances)
	}

	// Counters aggregate across instances; gauges do not.
	var totals []string
	for _, s := range summary.Totals {
		totals = append(totals, s.Name)
		if s.Name == "requests_total" {
			if s.Value != 8 {
				t.Errorf("total: got %v; want 8", s.Value)
			}
			if _, ok := s.Tags[scrape.InstanceTag]; ok {
				t.Error("total still carries an instance tag")
			}
			if got := s.Tags["route"]; got != "/a" {
				t.Errorf("total route tag: got %q; want %q", got, "/a")
			}
		}
	}
	if len(totals) != 1 || totals[0] != "requests_total" {
		t.Errorf("totals: got %v; want [requests_total]", totals)
	}
}

func TestCollector_MergesHistograms(t *testing.T) {
	t.Parallel()

	bounds := []float64{0.1, 1}
	one := endpoint(t, func(reg *metrics.Registry) {
		h := reg.Histogram("latency_seconds", bounds)
		h.Observe(0.05)
		h.Observe(0.5)
	})
	two := endpoint(t, func(reg *metrics.Registry) {
		h := reg.Histogram("latency_seconds", bounds)
		h.Observe(0.05)
	})

	c := scrape.New(scrape.WithLogger(log.Discard()))
	c.Add("api-1", one.URL)
	c.Add("api-2", two.URL)
	c.Run(t.Context())

	totals := c.Summary().Totals
	if len(totals) != 1 {
		t.Fatalf("totals: got %d; want 1", len(totals))
	}
	total := totals[0]

	if total.Count != 3 {
		t.Errorf("count: got %d; want 3", total.Count)
	}

	// Bucket-wise merge: bound 0.1 counts 2, bound 1 counts 3.
	if len(total.Buckets) != 2 {
		t.Fatalf("buckets: got %d; want 2", len(total.Buckets))
	}
	if got := total.Buckets[0].Count; got != 2 {
		t.Errorf("bucket 0.1: got %d; want 2", got)
	}
	if got := total.Buckets[1].Count; got != 3 {
		t.Errorf("bucket 1: got %d; want 3", got)
	}
}

func TestCollector_ReportsFailures(t *testing.T) {
	t.Parallel()

	up := endpoint(t, func(reg *metrics.Registry) {
		reg.Counter("requests_total").Add(1)
	})
	down := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	))
	defer down.Close()

	c := scrape.New(scrape.WithLogger(log.Discard()))
	c.Add("up", up.URL)
	c.Add("down", down.URL)
	c.Run(t.Context())

	summary := c.Summary()
	status := make(map[string]scrape.Target)
	for _, target := range summary.Targets {
		status[target.Name] = target
	}

	if !status["up"].Up {
		t.Error("up target: got down; want up")
	}
	if status["down"].Up {
		t.Error("down target: got up; want down")
	}
	if status["down"].Error == "" {
		t.Error("down target: error missing")
	}

	// Only the healthy target contributes samples.
	if got := len(summary.Metrics); got != 1 {
		t.Errorf("metrics: got %d; want 1", got)
	}
}

func TestCollector_KeepsLastSnapshotAcrossFailures(t *testing.T) {
	t.Parallel()

	// The target serves one good snapshot, then breaks.
	var fail bool
	reg := metrics.NewRegistry()
	reg.Counter("requests_total").Add(9)
	inner := reg.Handler()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if fail {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			inner.ServeHTTP(w, r)
		},
	))
	defer srv.Close()

	c := scrape.New(scrape.WithLogger(log.Discard()))
	c.Add("api", srv.URL)

	c.Run(t.Context())
	fail = true
	c.Run(t.Context())

	summary := c.Summary()
	if summary.Targets[0].Up {
		t.Error("target: got up; want down")
	}

	// The stale snapshot is retained so the summary degrades gracefully.
	if got := len(summary.Metrics); got != 1 {
		t.Fatalf("metrics: got %d; want 1", got)
	}
	if got := summary.Metrics[0].Value; got != 9 {
		t.Errorf("value: got %v; want 9", got)
	}
}

func TestCollector_PanicsOnDuplicateName(t *testing.T) {
	t.Parallel()

	c := scrape.New()
	c.Add("api", "http://one")

	defer func() {
		if recover() == nil {
			t.Error("should have panicked on duplicate target name")
		}
	}()
	c.Add("api", "http://two")
}

func TestCollector_Mount(t *testing.T) {
	t.Parallel()

	one := endpoint(t, func(reg *metrics.Registry) {
		reg.Counter("requests_total").Add(2)
	})

	c := scrape.New(scrape.WithLogger(log.Discard()))
	c.Add("api", one.URL)
	c.Run(t.Context())

	r := router.New()
	c.Mount(r)

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d; want %d", res.StatusCode, http.StatusOK)
	}

	var summary scrape.Summary
	if err := json.UnmarshalRead(res.Body, &summary); err != nil {
		t.Fatalf("decoding summary: %v", err)
	}
	if got := len(summary.Targets); got != 1 {
		t.Errorf("targets: got %d; want 1", got)
	}
	if got := len(summary.Totals); got != 1 {
		t.Errorf("totals: got %d; want 1", got)
	}
}
