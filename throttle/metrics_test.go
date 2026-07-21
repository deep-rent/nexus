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

package throttle_test

import (
	"context"
	"testing"

	"github.com/deep-rent/nexus/throttle"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// throttleCounts collects the named counter grouped by the string form of
// the "allowed" attribute; data points without it land under "".
func throttleCounts(
	t *testing.T,
	reader *sdkmetric.ManualReader,
	name string,
) (counts map[string]int64, throttleName string) {
	t.Helper()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	counts = make(map[string]int64)
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
				outcome := ""
				if v, ok := dp.Attributes.Value("allowed"); ok {
					outcome = v.Emit()
				}
				counts[outcome] += dp.Value
				if v, ok := dp.Attributes.Value("throttle"); ok {
					throttleName = v.Emit()
				}
			}
		}
	}
	return counts, throttleName
}

func TestThrottle_CountsDecisions(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	th := throttle.New(throttle.Config{
		Rate:          1,
		Burst:         2,
		Name:          "login",
		MeterProvider: mp,
	})

	// The burst of 2 admits two spends; the third is rejected.
	for range 2 {
		if !th.Allow("alice") {
			t.Fatal("allow: got false; want true")
		}
	}
	if th.Allow("alice") {
		t.Fatal("allow: got true; want false")
	}

	counts, name := throttleCounts(t, reader, "nexus.throttle.decision")
	if got := counts["true"]; got != 2 {
		t.Errorf("allowed: got %d; want 2", got)
	}
	if got := counts["false"]; got != 1 {
		t.Errorf("rejected: got %d; want 1", got)
	}
	if name != "login" {
		t.Errorf("throttle attribute: got %q; want %q", name, "login")
	}
}

func TestThrottle_CountsPenalties(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	th := throttle.New(throttle.Config{MeterProvider: mp})

	th.Penalize("alice", 10)
	th.Penalize("alice", 0) // A non-positive charge is not counted.

	counts, _ := throttleCounts(t, reader, "nexus.throttle.penalty")
	if got := counts[""]; got != 1 {
		t.Errorf("penalties: got %d; want 1", got)
	}
}
