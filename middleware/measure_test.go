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

package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/metrics"
	mw "github.com/deep-rent/nexus/middleware"
)

// durations returns the request duration samples recorded in reg, keyed by
// "method route status".
func durations(t *testing.T, reg *metrics.Registry) map[string]uint64 {
	t.Helper()

	got := make(map[string]uint64)
	for _, s := range reg.Snapshot().Metrics {
		if s.Name != mw.RequestDuration {
			continue
		}
		key := s.Tags["method"] + " " + s.Tags["route"] +
			" " + s.Tags["status"]
		got[key] = s.Count
	}
	return got
}

func TestMeasure_RecordsRequest(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	mux := http.NewServeMux()
	mux.Handle("GET /users/{id}", mockHandler)

	h := mw.Chain(mux, mw.Measure(mw.WithRegistry(reg)))
	h.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/users/42", nil),
	)

	// Adjacent to the mux, the route falls out of the request pattern,
	// stripped of its leading method.
	want := "GET /users/{id} 200"
	if got := durations(t, reg); got[want] != 1 {
		t.Errorf("samples: got %v; want %q once", got, want)
	}
}

func TestMeasure_UsesRecordedRoute(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	h := mw.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw.SetRoute(r.Context(), "/users/{id}")
			w.WriteHeader(http.StatusCreated)
		}),
		mw.Measure(mw.WithRegistry(reg)),
		// An intermediate context clone must not hide the route.
		mw.RequestID(),
	)

	h.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/users/42", nil),
	)

	want := "POST /users/{id} 201"
	if got := durations(t, reg); got[want] != 1 {
		t.Errorf("samples: got %v; want %q once", got, want)
	}
}

func TestMeasure_SkipsExcludedRequests(t *testing.T) {
	t.Parallel()

	t.Run("skip paths", func(t *testing.T) {
		t.Parallel()

		reg := metrics.NewRegistry()
		h := mw.Chain(
			mockHandler,
			mw.Measure(mw.WithRegistry(reg), mw.WithSkip("/health")),
		)

		h.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/health", nil),
		)

		if got := durations(t, reg); len(got) != 0 {
			t.Errorf("samples: got %v; want none", got)
		}
	})

	t.Run("filter", func(t *testing.T) {
		t.Parallel()

		reg := metrics.NewRegistry()
		keep := func(r *http.Request) bool {
			return r.Method != http.MethodGet
		}
		h := mw.Chain(
			mockHandler,
			mw.Measure(mw.WithRegistry(reg), mw.WithFilter(keep)),
		)

		h.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/", nil),
		)

		if got := durations(t, reg); len(got) != 0 {
			t.Errorf("samples: got %v; want none", got)
		}
	})
}

func TestMeasure_RecordsPanicsAsServerErrors(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	h := mw.Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom")
		}),
		mw.Recover(mockLogger(&bytes.Buffer{})),
		mw.Measure(mw.WithRegistry(reg)),
	)

	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))

	// Recover outside Measure still converts the re-raised panic into a
	// 500 response.
	if got := res.Code; got != http.StatusInternalServerError {
		t.Errorf(
			"response: got %d; want %d",
			got, http.StatusInternalServerError,
		)
	}

	want := "GET  500"
	if got := durations(t, reg); got[want] != 1 {
		t.Errorf("samples: got %v; want %q once", got, want)
	}
}

func TestRoute_WithoutHolder(t *testing.T) {
	t.Parallel()

	// Outside a measured request, SetRoute is a no-op and GetRoute is
	// empty.
	mw.SetRoute(t.Context(), "/users/{id}")
	if got := mw.GetRoute(t.Context()); got != "" {
		t.Errorf("route: got %q; want %q", got, "")
	}
}
