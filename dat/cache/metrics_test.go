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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/dat/cache"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
)

// refreshCounts collects the refresh counter grouped by outcome.
func refreshCounts(
	t *testing.T,
	reg *metrics.Registry,
) map[string]uint64 {
	t.Helper()

	counts := make(map[string]uint64)
	for _, s := range reg.Snapshot().Metrics {
		if s.Name != cache.Refreshes {
			continue
		}
		counts[s.Tags["outcome"]] += uint64(s.Value)
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

	reg := metrics.NewRegistry()
	c := cache.NewController(
		srv.URL,
		func(r *cache.Response) (string, error) { return string(r.Body), nil },
		cache.WithClient(srv.Client()),
		cache.WithLogger(log.Silent()),
		cache.WithRegistry(reg),
	)

	for range 3 {
		c.Run(t.Context())
	}

	counts := refreshCounts(t, reg)
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
