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

package transport_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/net/retry"
	"github.com/deep-rent/nexus/net/transport"
)

// requestSamples returns the client duration samples recorded in reg, keyed
// by "method status".
func requestSamples(t *testing.T, reg *metrics.Registry) map[string]uint64 {
	t.Helper()

	got := make(map[string]uint64)
	for _, s := range reg.Snapshot().Metrics {
		if s.Name != transport.RequestDuration {
			continue
		}
		got[s.Tags["method"]+" "+s.Tags["status"]] = s.Count
	}
	return got
}

func TestMetrics_RecordsRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))
	defer srv.Close()

	reg := metrics.NewRegistry()
	client := &http.Client{
		Transport: transport.New(
			transport.WithMetrics(transport.WithRegistry(reg)),
		),
	}

	res, err := client.Get(srv.URL + "/things")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	res.Body.Close()

	if got := requestSamples(t, reg); got["GET 200"] != 1 {
		t.Errorf("samples: got %v; want %q once", got, "GET 200")
	}

	// The host tag carries the target hostname.
	for _, s := range reg.Snapshot().Metrics {
		if s.Name == transport.RequestDuration {
			if got := s.Tags["host"]; got != "127.0.0.1" {
				t.Errorf("host: got %q; want %q", got, "127.0.0.1")
			}
		}
	}
}

func TestMetrics_RecordsEachRetryAttempt(t *testing.T) {
	t.Parallel()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	))
	defer srv.Close()

	reg := metrics.NewRegistry()
	client := &http.Client{
		Transport: transport.New(
			transport.WithMetrics(transport.WithRegistry(reg)),
			transport.WithRetry(retry.WithAttemptLimit(3)),
		),
	}

	res, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	res.Body.Close()

	if calls != 3 {
		t.Fatalf("calls: got %d; want 3", calls)
	}

	// The measuring layer sits below retry, so every attempt is observed.
	if got := requestSamples(t, reg); got["GET 503"] != 3 {
		t.Errorf("samples: got %v; want %q thrice", got, "GET 503")
	}
}

func TestMetrics_RecordsTransportErrors(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	client := &http.Client{
		Transport: transport.New(
			transport.WithMetrics(transport.WithRegistry(reg)),
		),
	}

	// The address is unroutable, so the dial fails.
	res, err := client.Get("http://127.0.0.1:1")
	if err == nil {
		res.Body.Close()
		t.Fatal("should have returned an error")
	}

	if got := requestSamples(t, reg); got["GET error"] != 1 {
		t.Errorf("samples: got %v; want %q once", got, "GET error")
	}
}
