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

// Package metrics provides a lightweight, dependency-free registry of tagged
// metric primitives — counters, gauges, histograms, meters, and timers —
// together with a JSON collection endpoint for exposing snapshots over HTTP.
//
// The design follows the Prometheus pull model: instruments accumulate state
// in memory at negligible cost, and a scraper reads point-in-time snapshots
// from the /metrics endpoint. The subpackage scrape provides such a scraper,
// including a merged summary view across multiple application instances.
//
// # Instruments
//
//   - [Counter]: a monotonically increasing count.
//   - [Gauge]: a value that can go up and down.
//   - [Histogram]: a distribution of observations in fixed buckets.
//   - [Meter]: a count with exponentially weighted moving rates.
//   - [Timer]: a histogram of durations combined with a rate meter.
//
// All instruments are safe for concurrent use, and their hot paths are
// implemented with atomic operations only — no locks are taken while
// recording. Locks guard registration and snapshotting, which are cold
// paths.
//
// # Usage
//
// Instruments are obtained from a [Registry] once, typically at construction
// time, and then recorded against directly:
//
//	requests := metrics.DefaultRegistry.Counter(
//		"requests_total", metrics.T("route", "/users"),
//	)
//
//	func handle() {
//		requests.Inc()
//	}
//
// Obtaining the same name and tags again returns the same instrument, so
// packages need not coordinate. Instrumented packages in this module default
// to [DefaultRegistry] and accept a *[Registry] option to make the
// destination configurable.
//
// # Exposure
//
// [Registry.Handler] serves the current snapshot as JSON. Mount it on a
// router to expose the conventional collection endpoint:
//
//	r := router.New()
//	r.Mount("GET /metrics", metrics.DefaultRegistry.Handler())
//
// # Naming
//
// Metric names follow the Prometheus conventions: snake_case, unit suffixes
// ("_seconds", "_bytes"), and "_total" for counters. Tags hold everything
// variable ("route", "status"), and their cardinality should stay small:
// every distinct tag combination materializes its own instrument.
package metrics

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Tag is a key/value pair qualifying a metric, comparable to a Prometheus
// label. Instruments with the same name but different tags are independent.
type Tag struct {
	Key   string
	Value string
}

// T builds a [Tag]. It reads better than a keyed struct literal at call
// sites, which tend to stack several tags:
//
//	reg.Counter("requests_total", metrics.T("route", "/users"))
func T(key, value string) Tag {
	return Tag{Key: key, Value: value}
}

// Kind identifies the type of an instrument.
type Kind uint8

const (
	// KindCounter identifies a [Counter].
	KindCounter Kind = iota
	// KindGauge identifies a [Gauge].
	KindGauge
	// KindHistogram identifies a [Histogram].
	KindHistogram
	// KindMeter identifies a [Meter].
	KindMeter
	// KindTimer identifies a [Timer].
	KindTimer
)

// String returns the lower-case name of the kind.
func (k Kind) String() string {
	switch k {
	case KindCounter:
		return "counter"
	case KindGauge:
		return "gauge"
	case KindHistogram:
		return "histogram"
	case KindMeter:
		return "meter"
	case KindTimer:
		return "timer"
	default:
		return "unknown"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k Kind) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Kind) UnmarshalText(text []byte) error {
	switch string(text) {
	case "counter":
		*k = KindCounter
	case "gauge":
		*k = KindGauge
	case "histogram":
		*k = KindHistogram
	case "meter":
		*k = KindMeter
	case "timer":
		*k = KindTimer
	default:
		return fmt.Errorf("invalid metric kind %q", text)
	}
	return nil
}

// instrument is the interface shared by all primitives, used internally by
// the registry to take snapshots.
type instrument interface {
	kind() Kind
	// sample fills the kind-specific fields of a snapshot sample.
	sample(s *Sample)
}

// entry pairs an instrument with its identity for snapshotting.
type entry struct {
	name string
	tags []Tag // sorted by key
	inst instrument
}

// Registry is a collection of named, tagged instruments. The zero value is
// not usable; create one with [NewRegistry] or use [DefaultRegistry].
//
// Lookup methods return the existing instrument when the same name and tags
// are requested again, and panic if the name and tags are already registered
// under a different kind — mixing kinds under one identity is a programming
// error that would silently corrupt the exposition otherwise.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]entry
}

// NewRegistry creates an empty [Registry].
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]entry)}
}

// DefaultRegistry is the registry used by instrumented packages in this
// module unless overridden. Applications that only ever need one registry
// can use it exclusively.
var DefaultRegistry = NewRegistry()

// identity renders the canonical key of an instrument: the name followed by
// its tags sorted by key. The tags slice is sorted in place.
func identity(name string, tags []Tag) string {
	if len(tags) == 0 {
		return name
	}
	slices.SortFunc(tags, func(a, b Tag) int {
		return strings.Compare(a.Key, b.Key)
	})

	var b strings.Builder
	b.Grow(len(name) + 16*len(tags))
	b.WriteString(name)
	b.WriteByte('{')
	for i, t := range tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(t.Key)
		b.WriteByte('=')
		b.WriteString(t.Value)
	}
	b.WriteByte('}')
	return b.String()
}

// lookup returns the instrument registered under name and tags, creating it
// with make if absent. It panics on a kind mismatch.
func (r *Registry) lookup(
	name string,
	tags []Tag,
	kind Kind,
	make func() instrument,
) instrument {
	tags = slices.Clone(tags)
	id := identity(name, tags)

	r.mu.RLock()
	e, ok := r.entries[id]
	r.mu.RUnlock()

	if !ok {
		r.mu.Lock()
		if e, ok = r.entries[id]; !ok {
			e = entry{name: name, tags: tags, inst: make()}
			r.entries[id] = e
		}
		r.mu.Unlock()
	}

	if got := e.inst.kind(); got != kind {
		panic(fmt.Sprintf(
			"metrics: %s already registered as %s, requested as %s",
			id, got, kind,
		))
	}
	return e.inst
}

// Counter returns the counter registered under the given name and tags,
// creating it on first use.
func (r *Registry) Counter(name string, tags ...Tag) *Counter {
	return r.lookup(name, tags, KindCounter, func() instrument {
		return &Counter{}
	}).(*Counter)
}

// Gauge returns the gauge registered under the given name and tags, creating
// it on first use.
func (r *Registry) Gauge(name string, tags ...Tag) *Gauge {
	return r.lookup(name, tags, KindGauge, func() instrument {
		return &Gauge{}
	}).(*Gauge)
}

// Histogram returns the histogram registered under the given name and tags,
// creating it on first use with the given bucket upper bounds. The bounds of
// an existing histogram are left untouched, so callers must agree on them.
// Passing no bounds uses [DefaultDurationBuckets].
func (r *Registry) Histogram(
	name string,
	bounds []float64,
	tags ...Tag,
) *Histogram {
	return r.lookup(name, tags, KindHistogram, func() instrument {
		return newHistogram(bounds)
	}).(*Histogram)
}

// Meter returns the meter registered under the given name and tags, creating
// it on first use.
func (r *Registry) Meter(name string, tags ...Tag) *Meter {
	return r.lookup(name, tags, KindMeter, func() instrument {
		return newMeter()
	}).(*Meter)
}

// Timer returns the timer registered under the given name and tags, creating
// it on first use. Durations are observed in seconds using
// [DefaultDurationBuckets].
func (r *Registry) Timer(name string, tags ...Tag) *Timer {
	return r.lookup(name, tags, KindTimer, func() instrument {
		return &Timer{
			hist:  newHistogram(nil),
			meter: newMeter(),
		}
	}).(*Timer)
}
