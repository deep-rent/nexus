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
	"testing"

	"github.com/deep-rent/nexus/sys/event"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
)

// counterValue returns the value of the named counter along with its bus
// tag; both are zero-valued if the counter was never recorded.
func counterValue(
	t *testing.T,
	reg *metrics.Registry,
	name string,
) (total uint64, bus string) {
	t.Helper()

	for _, s := range reg.Snapshot().Metrics {
		if s.Name != name {
			continue
		}
		total += uint64(s.Value)
		bus = s.Tags["bus"]
	}
	return total, bus
}

func TestBus_CountsPublishAndDelivery(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	bus := event.NewBus[int](
		event.WithRegistry(reg),
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

	published, name := counterValue(t, reg, event.BusPublished)
	if published != 3 {
		t.Errorf("published: got %d; want 3", published)
	}
	if name != "orders" {
		t.Errorf("bus tag: got %q; want %q", name, "orders")
	}

	delivered, _ := counterValue(t, reg, event.BusDelivered)
	if delivered != 3 {
		t.Errorf("delivered: got %d; want 3", delivered)
	}

	// Publishing after Close is rejected and counted as dropped.
	if bus.Publish(4) {
		t.Error("publish after close: got true; want false")
	}
	dropped, _ := counterValue(t, reg, event.BusDropped)
	if dropped != 1 {
		t.Errorf("dropped: got %d; want 1", dropped)
	}
}

func TestBus_CountsSubscriberPanics(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	bus := event.NewBus[int](
		event.WithRegistry(reg),
		event.WithLogger(log.Silent()),
		event.WithSyncDispatch(),
	)

	bus.Subscribe(func(int) { panic("boom") })

	if !bus.Publish(1) {
		t.Fatal("publish: got false; want true")
	}
	bus.Close()

	panics, _ := counterValue(t, reg, event.BusPanics)
	if panics != 1 {
		t.Errorf("panics: got %d; want 1", panics)
	}
	delivered, _ := counterValue(t, reg, event.BusDelivered)
	if delivered != 0 {
		t.Errorf("delivered: got %d; want 0", delivered)
	}
}

func TestBroker_NamesBusesAfterTopics(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	broker := event.NewBroker(event.WithRegistry(reg))
	bus := event.Topic[string](broker, "invoices")

	if !bus.Publish("total") {
		t.Fatal("publish: got false; want true")
	}
	broker.Close()

	published, name := counterValue(t, reg, event.BusPublished)
	if published != 1 {
		t.Errorf("published: got %d; want 1", published)
	}
	if name != "invoices" {
		t.Errorf("bus tag: got %q; want %q", name, "invoices")
	}
}
