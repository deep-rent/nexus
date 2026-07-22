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
	"encoding/json/v2"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Snapshot is a point-in-time view of every instrument in a [Registry],
// ordered deterministically by name and tags.
type Snapshot struct {
	// Time is when the snapshot was taken.
	Time time.Time `json:"time"`
	// Metrics holds one sample per registered instrument.
	Metrics []Sample `json:"metrics"`
}

// Sample is the state of a single instrument. Which fields are populated
// depends on the kind:
//
//   - counter, gauge: Value
//   - histogram: Count, Sum, Buckets
//   - meter: Count, Rates
//   - timer: Count, Sum, Buckets, Rates
type Sample struct {
	// Name is the metric name.
	Name string `json:"name"`
	// Kind identifies the instrument type.
	Kind Kind `json:"kind"`
	// Tags qualify the sample; see [Tag].
	Tags map[string]string `json:"tags,omitempty"`
	// Value is the current count or gauge level.
	Value float64 `json:"value,omitempty"`
	// Count is the number of recorded observations or events.
	Count uint64 `json:"count,omitempty"`
	// Sum is the sum of all recorded observations.
	Sum float64 `json:"sum,omitempty"`
	// Buckets are cumulative bucket counts; see [Bucket].
	Buckets []Bucket `json:"buckets,omitempty"`
	// Rates are moving average event rates; see [Rates].
	Rates *Rates `json:"rates,omitempty"`
}

// Bucket is one cumulative histogram bucket: the number of observations
// less than or equal to its upper bound. Only the finite bounds are listed;
// observations above the highest bound are the difference between the
// sample's total Count and the last bucket's Count.
type Bucket struct {
	// Bound is the inclusive upper bound.
	Bound float64 `json:"le"`
	// Count is the cumulative number of observations up to the bound.
	Count uint64 `json:"count"`
}

// Rates are exponentially weighted moving average rates in events per
// second, over 1-, 5-, and 15-minute windows, plus the lifetime mean.
type Rates struct {
	M01  float64 `json:"m01"`
	M05  float64 `json:"m05"`
	M15  float64 `json:"m15"`
	Mean float64 `json:"mean"`
}

// Snapshot captures the current state of every registered instrument.
// Instruments keep recording while the snapshot is taken; each sample is
// individually consistent, the set as a whole is approximate — the usual
// contract of a scrape.
func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	entries := make([]entry, 0, len(r.entries))
	for _, e := range r.entries {
		entries = append(entries, e)
	}
	r.mu.RUnlock()

	slices.SortFunc(entries, func(a, b entry) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return slices.CompareFunc(a.tags, b.tags, func(x, y Tag) int {
			if c := strings.Compare(x.Key, y.Key); c != 0 {
				return c
			}
			return strings.Compare(x.Value, y.Value)
		})
	})

	samples := make([]Sample, len(entries))
	for i, e := range entries {
		s := Sample{Name: e.name, Kind: e.inst.kind()}
		if len(e.tags) > 0 {
			s.Tags = make(map[string]string, len(e.tags))
			for _, t := range e.tags {
				s.Tags[t.Key] = t.Value
			}
		}
		e.inst.sample(&s)
		samples[i] = s
	}

	return Snapshot{Time: time.Now().UTC(), Metrics: samples}
}

// Handler returns an [http.Handler] serving the registry's current
// [Snapshot] as JSON — the collection endpoint a scraper polls. Mount it on
// a router under the conventional path:
//
//	r.Mount("GET /metrics", metrics.DefaultRegistry.Handler())
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.MarshalWrite(w, r.Snapshot()); err != nil {
			// The status line is already written; the client sees a
			// truncated body and discards the scrape.
			return
		}
	})
}
