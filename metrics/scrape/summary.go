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

package scrape

import (
	"encoding/json/v2"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/deep-rent/nexus/metrics"
	"github.com/deep-rent/nexus/router"
)

// InstanceTag is the tag key under which merged samples carry the name of
// the target they came from.
const InstanceTag = "instance"

// Summary is a merged view over the latest snapshots of every target.
type Summary struct {
	// Time is when the summary was assembled.
	Time time.Time `json:"time"`
	// Targets reports the scrape status of every registered endpoint.
	Targets []Target `json:"targets"`
	// Metrics is the union of all target samples, each tagged with its
	// instance name under [InstanceTag].
	Metrics []metrics.Sample `json:"metrics"`
	// Totals aggregates counter-like samples (counters, histograms, meters,
	// timers) across instances by name and tags. Gauges are omitted: sums
	// of point-in-time levels from different instances rarely mean
	// anything.
	Totals []metrics.Sample `json:"totals"`
}

// Target is the scrape status of one registered endpoint.
type Target struct {
	// Name is the instance name given to [Collector.Add].
	Name string `json:"name"`
	// URL is the scraped collection endpoint.
	URL string `json:"url"`
	// Up reports whether the most recent scrape succeeded.
	Up bool `json:"up"`
	// Error carries the failure of the most recent scrape, if any.
	Error string `json:"error,omitempty"`
	// Scraped is when the most recent scrape finished; zero if the target
	// has never been scraped.
	Scraped time.Time `json:"scraped,omitzero"`
	// Duration is how long the most recent scrape took, in seconds.
	Duration float64 `json:"duration,omitempty"`
	// Snapshot is when the retained snapshot was taken by the target
	// itself; zero if none has been obtained yet.
	Snapshot time.Time `json:"snapshot,omitzero"`
}

// Summary assembles the merged view from the latest retained snapshots. A
// target that has never been scraped successfully contributes only its
// status.
func (c *Collector) Summary() Summary {
	c.mu.RLock()
	targets := c.targets
	c.mu.RUnlock()

	summary := Summary{
		Time:    time.Now().UTC(),
		Targets: make([]Target, 0, len(targets)),
	}

	for _, t := range targets {
		t.mu.Lock()
		status := Target{
			Name:     t.name,
			URL:      t.url,
			Up:       !t.scraped.IsZero() && t.err == nil,
			Scraped:  t.scraped,
			Duration: t.took.Seconds(),
		}
		if t.err != nil {
			status.Error = t.err.Error()
		}
		var snapshot *metrics.Snapshot
		if t.snapshot != nil {
			snapshot = t.snapshot
			status.Snapshot = t.snapshot.Time
		}
		t.mu.Unlock()

		summary.Targets = append(summary.Targets, status)
		if snapshot == nil {
			continue
		}

		for _, s := range snapshot.Metrics {
			tags := make(map[string]string, len(s.Tags)+1)
			maps.Copy(tags, s.Tags)
			tags[InstanceTag] = t.name
			s.Tags = tags
			summary.Metrics = append(summary.Metrics, s)
		}
	}

	summary.Totals = aggregate(summary.Metrics)
	return summary
}

// aggregate folds instance-tagged samples into per-family totals: counters,
// histogram counts and sums, and meter counts are added across instances;
// histogram buckets merge bucket-wise when the layouts agree, and are
// dropped for a family with mismatched layouts. Rates and gauges do not
// aggregate meaningfully and are omitted.
func aggregate(samples []metrics.Sample) []metrics.Sample {
	families := make(map[string]*metrics.Sample)
	order := make([]string, 0, len(samples))

	for _, s := range samples {
		if s.Kind == metrics.KindGauge {
			continue
		}

		tags := make(map[string]string, len(s.Tags))
		maps.Copy(tags, s.Tags)
		delete(tags, InstanceTag)
		id := familyID(s.Name, tags)

		total, ok := families[id]
		if !ok {
			families[id] = &metrics.Sample{
				Name:    s.Name,
				Kind:    s.Kind,
				Tags:    tags,
				Value:   s.Value,
				Count:   s.Count,
				Sum:     s.Sum,
				Buckets: slices.Clone(s.Buckets),
			}
			order = append(order, id)
			continue
		}

		total.Value += s.Value
		total.Count += s.Count
		total.Sum += s.Sum
		total.Buckets = mergeBuckets(total.Buckets, s.Buckets)
	}

	slices.Sort(order)
	totals := make([]metrics.Sample, len(order))
	for i, id := range order {
		totals[i] = *families[id]
	}
	return totals
}

// familyID renders the identity of a family: name plus sorted tags.
func familyID(name string, tags map[string]string) string {
	var b strings.Builder
	b.WriteString(name)
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		b.WriteByte(',')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(tags[k])
	}
	return b.String()
}

// mergeBuckets adds counts bucket-wise. Mismatched layouts yield nil, since
// adding counts across different bounds would fabricate a distribution.
func mergeBuckets(a, b []metrics.Bucket) []metrics.Bucket {
	if len(a) != len(b) {
		return nil
	}
	for i := range a {
		if a[i].Bound != b[i].Bound {
			return nil
		}
		a[i].Count += b[i].Count
	}
	return a
}

// Handler returns an [http.Handler] serving the current [Summary] as JSON.
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.MarshalWrite(w, c.Summary()); err != nil {
			// The status line is already written; the client sees a
			// truncated body and discards the read.
			return
		}
	})
}

// Mount registers the summary endpoint on the router under "GET /metrics",
// mirroring how a single instance exposes its own registry.
func (c *Collector) Mount(r *router.Router) {
	r.Mount("GET /metrics", c.Handler())
}
