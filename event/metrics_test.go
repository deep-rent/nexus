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

package event_test

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/deep-rent/nexus/event"
	"github.com/deep-rent/nexus/log"
)

// counterValue sums the data points of the named counter, returning the bus
// attribute alongside.
func counterValue(
	t *testing.T,
	reader *sdkmetric.ManualReader,
	name string,
) (total int64, bus string) {
	t.Helper()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				total += dp.Value
				if v, ok := dp.Attributes.Value("bus"); ok {
					bus = v.Emit()
				}
			}
		}
	}
	return total, bus
}

func TestBus_CountsPublishAndDelivery(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	bus := event.NewBus[int](
		event.WithMeterProvider(mp),
		event.WithName("orders"),
		event.WithSyncDispatch(),
	)

	var seen int
	bus.Subscribe(func(int) { seen++ })

	for i := range 3 {
		if !bus.Publish(i) {
			t.Fatalf("publish %d: got false; want true", i)
		}
	}
	bus.Close()

	if seen != 3 {
		t.Fatalf("deliveries: got %d; want 3", seen)
	}

	published, name := counterValue(t, reader, "nexus.event.published")
	if published != 3 {
		t.Errorf("published: got %d; want 3", published)
	}
	if name != "orders" {
		t.Errorf("bus attribute: got %q; want %q", name, "orders")
	}

	delivered, _ := counterValue(t, reader, "nexus.event.delivered")
	if delivered != 3 {
		t.Errorf("delivered: got %d; want 3", delivered)
	}

	// Publishing after Close is rejected and counted as dropped.
	if bus.Publish(4) {
		t.Error("publish after close: got true; want false")
	}
	dropped, _ := counterValue(t, reader, "nexus.event.dropped")
	if dropped != 1 {
		t.Errorf("dropped: got %d; want 1", dropped)
	}
}

func TestBus_CountsSubscriberPanics(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	bus := event.NewBus[int](
		event.WithMeterProvider(mp),
		event.WithLogger(log.Silent()),
		event.WithSyncDispatch(),
	)

	bus.Subscribe(func(int) { panic("boom") })

	if !bus.Publish(1) {
		t.Fatal("publish: got false; want true")
	}
	bus.Close()

	panics, _ := counterValue(t, reader, "nexus.event.panic")
	if panics != 1 {
		t.Errorf("panics: got %d; want 1", panics)
	}
	delivered, _ := counterValue(t, reader, "nexus.event.delivered")
	if delivered != 0 {
		t.Errorf("delivered: got %d; want 0", delivered)
	}
}

func TestBroker_NamesBusesAfterTopics(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	broker := event.NewBroker(event.WithMeterProvider(mp))
	bus := event.Topic[string](broker, "invoices")

	if !bus.Publish("total") {
		t.Fatal("publish: got false; want true")
	}
	broker.Close()

	published, name := counterValue(t, reader, "nexus.event.published")
	if published != 1 {
		t.Errorf("published: got %d; want 1", published)
	}
	if name != "invoices" {
		t.Errorf("bus attribute: got %q; want %q", name, "invoices")
	}
}
