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

package router_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/metrics"
	"github.com/deep-rent/nexus/net/middleware"
	"github.com/deep-rent/nexus/net/router"
)

// samples returns the request duration samples recorded in reg, keyed by
// "method route status".
func samples(t *testing.T, reg *metrics.Registry) map[string]uint64 {
	t.Helper()

	got := make(map[string]uint64)
	for _, s := range reg.Snapshot().Metrics {
		if s.Name != middleware.RequestDuration {
			continue
		}
		key := s.Tags["method"] + " " + s.Tags["route"] +
			" " + s.Tags["status"]
		got[key] = s.Count
	}
	return got
}

func TestMeasure_TagsRoutePattern(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	r := router.New(router.WithMiddleware(
		router.Measure(middleware.WithRegistry(reg)),
	))
	r.HandleFunc("GET /users/{id}", func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]string{"id": e.Param("id")})
	})

	res := httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/users/42", nil))

	if res.Code != http.StatusOK {
		t.Fatalf("status: got %d; want %d", res.Code, http.StatusOK)
	}

	want := "GET /users/{id} 200"
	if got := samples(t, reg); got[want] != 1 {
		t.Errorf("samples: got %v; want %q once", got, want)
	}
}

func TestMeasure_ObservesErrorHandlerStatus(t *testing.T) {
	t.Parallel()

	reg := metrics.NewRegistry()
	r := router.New(
		router.WithLogger(log.Silent()),
		router.WithMiddleware(router.Measure(middleware.WithRegistry(reg))),
	)
	r.HandleFunc("GET /boom", func(*router.Exchange) error {
		return router.ServerError(
			"something went wrong",
			errors.New("database exploded"),
		)
	})
	r.HandleFunc("GET /nope", func(*router.Exchange) error {
		return router.NotFound("no such thing")
	})

	for _, path := range []string{"/boom", "/nope"} {
		r.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, path, nil),
		)
	}

	// The error handler resolves inside the pipe, so the histogram sees
	// the final status codes.
	got := samples(t, reg)
	if got["GET /boom 500"] != 1 {
		t.Errorf("samples: got %v; want %q once", got, "GET /boom 500")
	}
	if got["GET /nope 404"] != 1 {
		t.Errorf("samples: got %v; want %q once", got, "GET /nope 404")
	}
}
