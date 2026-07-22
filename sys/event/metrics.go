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

package event

import (
	"github.com/deep-rent/nexus/sys/metrics"
)

// Names of the counters recorded by a [Bus], all tagged with the bus name
// set via [WithName].
const (
	// BusPublished counts events accepted by the bus.
	BusPublished = "event_published_total"
	// BusDropped counts events rejected because the bus was full or closed.
	// Note that under [DropOldest], the ring buffer evicts the displaced
	// event silently, so such evictions do not show up here; only rejected
	// publishes do.
	BusDropped = "event_dropped_total"
	// BusDelivered counts completed subscriber deliveries.
	BusDelivered = "event_delivered_total"
	// BusPanics counts subscriber deliveries that panicked.
	BusPanics = "event_panics_total"
)

// counters bundles the bus counters, resolved once at construction so the
// publish and delivery hot paths touch nothing but atomics.
type counters struct {
	published *metrics.Counter
	dropped   *metrics.Counter
	delivered *metrics.Counter
	panics    *metrics.Counter
}

// newCounters resolves the bus counters from the given registry.
func newCounters(reg *metrics.Registry, name string) *counters {
	tag := metrics.T("bus", name)
	return &counters{
		published: reg.Counter(BusPublished, tag),
		dropped:   reg.Counter(BusDropped, tag),
		delivered: reg.Counter(BusDelivered, tag),
		panics:    reg.Counter(BusPanics, tag),
	}
}
