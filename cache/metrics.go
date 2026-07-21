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

package cache

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// scope is the instrumentation scope reported for metrics emitted by this
// package.
const scope = "github.com/deep-rent/nexus/cache"

// stats counts refresh cycles by outcome under the "nexus.cache.refresh"
// counter, labeled with the resource URL.
type stats struct {
	counter   metric.Int64Counter
	updated   metric.MeasurementOption
	unchanged metric.MeasurementOption
	failed    metric.MeasurementOption
}

// newStats builds the refresh counter from the given provider.
func newStats(mp metric.MeterProvider, url string) stats {
	counter, err := mp.Meter(scope).Int64Counter(
		"nexus.cache.refresh",
		metric.WithDescription("Number of cache refresh cycles by outcome."),
	)
	if err != nil {
		otel.Handle(err)
		counter, _ = noop.NewMeterProvider().Meter(scope).Int64Counter("")
	}

	outcome := func(o string) metric.MeasurementOption {
		return metric.WithAttributes(
			attribute.String("url", url),
			attribute.String("outcome", o),
		)
	}
	return stats{
		counter:   counter,
		updated:   outcome("updated"),
		unchanged: outcome("unchanged"),
		failed:    outcome("error"),
	}
}

// count records one refresh cycle with the given outcome.
func (s stats) count(ctx context.Context, outcome metric.MeasurementOption) {
	s.counter.Add(ctx, 1, outcome)
}
