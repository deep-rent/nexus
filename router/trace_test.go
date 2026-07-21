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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/router"
)

// recordSpans returns a span recorder together with the Trace middleware
// wired to it.
func recordSpans(t *testing.T) (*tracetest.SpanRecorder, router.Middleware) {
	t.Helper()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	return spans, router.Trace(middleware.WithTracerProvider(tp))
}

// spanAttr returns the string form of an attribute recorded on a span, or
// the empty string if the key is absent.
func spanAttr(s sdktrace.ReadOnlySpan, key attribute.Key) string {
	for _, kv := range s.Attributes() {
		if kv.Key == key {
			return kv.Value.Emit()
		}
	}
	return ""
}

func TestTrace_NamesSpanAfterPattern(t *testing.T) {
	t.Parallel()

	spans, trace := recordSpans(t)
	r := router.New(router.WithMiddleware(trace))
	r.HandleFunc("GET /users/{id}", func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]string{"id": e.Param("id")})
	})

	res := httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/users/42", nil))

	if res.Code != http.StatusOK {
		t.Fatalf("status: got %d; want %d", res.Code, http.StatusOK)
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("spans: got %d; want 1", len(ended))
	}
	span := ended[0]

	if got, want := span.Name(), "GET /users/{id}"; got != want {
		t.Errorf("name: got %q; want %q", got, want)
	}
	if got, want := spanAttr(
		span,
		"http.route",
	), "GET /users/{id}"; got != want {
		t.Errorf("http.route: got %q; want %q", got, want)
	}
}

func TestTrace_StampsServerErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("database exploded")

	spans, trace := recordSpans(t)
	r := router.New(
		router.WithLogger(log.Silent()),
		router.WithMiddleware(trace),
	)
	r.HandleFunc("GET /boom", func(*router.Exchange) error {
		return router.ServerError("something went wrong", cause)
	})

	res := httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if res.Code != http.StatusInternalServerError {
		t.Fatalf(
			"status: got %d; want %d",
			res.Code, http.StatusInternalServerError,
		)
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("spans: got %d; want 1", len(ended))
	}
	span := ended[0]

	if got := span.Status().Code; got != codes.Error {
		t.Errorf("status: got %v; want %v", got, codes.Error)
	}

	// The error handler resolves inside the pipe, so the span observes the
	// final status code.
	if got := spanAttr(span, "http.response.status_code"); got != "500" {
		t.Errorf("status attr: got %q; want %q", got, "500")
	}

	// The generated error ID links the span to the client-reported value.
	if got := spanAttr(span, "error.id"); got == "" {
		t.Error("error.id: got empty; want a generated ID")
	}

	// The cause is recorded as an exception event on the span.
	var found bool
	for _, ev := range span.Events() {
		if ev.Name != "exception" {
			continue
		}
		for _, kv := range ev.Attributes {
			if kv.Key == "exception.message" &&
				kv.Value.Emit() == cause.Error() {
				found = true
			}
		}
	}
	if !found {
		t.Error("exception event with the cause message not found")
	}
}

func TestTrace_LeavesClientErrorsUnmarked(t *testing.T) {
	t.Parallel()

	spans, trace := recordSpans(t)
	r := router.New(
		router.WithLogger(log.Silent()),
		router.WithMiddleware(trace),
	)
	r.HandleFunc("GET /nope", func(*router.Exchange) error {
		return router.NotFound("no such thing")
	})

	res := httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if res.Code != http.StatusNotFound {
		t.Fatalf("status: got %d; want %d", res.Code, http.StatusNotFound)
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("spans: got %d; want 1", len(ended))
	}
	span := ended[0]

	// A 404 is ordinary traffic on a public API, not a span failure.
	if got := span.Status().Code; got == codes.Error {
		t.Errorf("status: got %v; want not %v", got, codes.Error)
	}
	if got := spanAttr(span, "http.response.status_code"); got != "404" {
		t.Errorf("status attr: got %q; want %q", got, "404")
	}
}
