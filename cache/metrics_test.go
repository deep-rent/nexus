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

package cache_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// refreshCounts collects the nexus.cache.refresh counter grouped by outcome.
func refreshCounts(
	t *testing.T,
	reader *sdkmetric.ManualReader,
) map[string]int64 {
	t.Helper()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	counts := make(map[string]int64)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "nexus.cache.refresh" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value("outcome"); ok {
					counts[v.Emit()] += dp.Value
				}
			}
		}
	}
	return counts
}

func TestController_CountsRefreshOutcomes(t *testing.T) {
	t.Parallel()

	// The resource is served once, reported unchanged once, and then breaks.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			calls++
			switch calls {
			case 1:
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write([]byte("payload"))
			case 2:
				w.WriteHeader(http.StatusNotModified)
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		},
	))
	defer srv.Close()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	c := cache.NewController(
		srv.URL,
		func(r *cache.Response) (string, error) { return string(r.Body), nil },
		cache.WithClient(srv.Client()),
		cache.WithLogger(log.Silent()),
		cache.WithMeterProvider(mp),
	)

	for range 3 {
		c.Run(t.Context())
	}

	counts := refreshCounts(t, reader)
	if got := counts["updated"]; got != 1 {
		t.Errorf("updated: got %d; want 1", got)
	}
	if got := counts["unchanged"]; got != 1 {
		t.Errorf("unchanged: got %d; want 1", got)
	}
	if got := counts["error"]; got != 1 {
		t.Errorf("error: got %d; want 1", got)
	}
}
