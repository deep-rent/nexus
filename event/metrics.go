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
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// scope is the instrumentation scope reported for metrics emitted by this
// package.
const scope = "github.com/deep-rent/nexus/event"

// counters bundles the bus metrics. Events carry no context, so recording
// uses the background context; the bus name set via [WithName] is what keeps
// instances distinguishable.
//
// Note that under [DropOldest], the ring buffer evicts the displaced event
// silently, so such evictions do not show up in the dropped counter; only
// rejected publishes do.
type counters struct {
	attrs     metric.MeasurementOption
	published metric.Int64Counter
	dropped   metric.Int64Counter
	delivered metric.Int64Counter
	panics    metric.Int64Counter
}

// newCounters builds the bus counters from the given provider.
func newCounters(mp metric.MeterProvider, name string) *counters {
	meter := mp.Meter(scope)
	count := func(instrument, description string) metric.Int64Counter {
		counter, err := meter.Int64Counter(
			instrument,
			metric.WithDescription(description),
		)
		if err != nil {
			otel.Handle(err)
			counter, _ = noop.NewMeterProvider().Meter(scope).Int64Counter("")
		}
		return counter
	}
	return &counters{
		attrs: metric.WithAttributes(attribute.String("bus", name)),
		published: count(
			"nexus.event.published",
			"Number of events accepted by the bus.",
		),
		dropped: count(
			"nexus.event.dropped",
			"Number of events rejected because the bus was full or closed.",
		),
		delivered: count(
			"nexus.event.delivered",
			"Number of completed subscriber deliveries.",
		),
		panics: count(
			"nexus.event.panic",
			"Number of subscriber deliveries that panicked.",
		),
	}
}

// add increments a counter by one. Counter values are monotonic sums, so the
// background context carries no information worth threading through.
func (c *counters) add(counter metric.Int64Counter) {
	counter.Add(context.Background(), 1, c.attrs)
}
