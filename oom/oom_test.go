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

package oom

import (
	"math"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"testing"

	"github.com/deep-rent/nexus/router"
)

func TestMiddleware_NoLimit(t *testing.T) {
	t.Parallel()
	// Ensure no limit is set for this test.
	prev := debug.SetMemoryLimit(math.MaxInt64)
	defer func() {
		_ = debug.SetMemoryLimit(prev)
	}()

	mw := Middleware()

	handler := mw(router.HandlerFunc(func(e *router.Exchange) error {
		e.W.WriteHeader(http.StatusOK)
		return nil
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e := &router.Exchange{
		R: req,
		W: router.NewResponseWriter(rec),
	}

	err := handler.ServeHTTP(e)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if exp, act := http.StatusOK, rec.Code; exp != act {
		t.Fatalf("expected status %d, got %d", exp, act)
	}
}

func TestMiddleware_Overloaded(t *testing.T) {
	t.Parallel()

	// Set a very small memory limit (1000 bytes) for testing.
	prev := debug.SetMemoryLimit(1000)
	defer func() {
		_ = debug.SetMemoryLimit(prev)
	}()

	// Fake the memory provider to report 950 bytes in use (95% of 1000).
	mw := Middleware(
		WithMemoryProvider(func() uint64 {
			return 950
		}),
	)

	handler := mw(router.HandlerFunc(func(e *router.Exchange) error {
		e.W.WriteHeader(http.StatusOK)
		return nil
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e := &router.Exchange{
		R: req,
		W: router.NewResponseWriter(rec),
	}

	err := handler.ServeHTTP(e)

	// We expect a router.Error indicating 503.
	var rErr *router.Error
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	rErr, ok := err.(*router.Error)
	if !ok {
		t.Fatalf("expected *router.Error, got %T: %v", err, err)
	}

	if exp, act := http.StatusServiceUnavailable, rErr.Status; exp != act {
		t.Fatalf("expected status %d, got %d", exp, act)
	}
	if exp, act := ReasonOverload, rErr.Reason; exp != act {
		t.Fatalf("expected reason %s, got %s", exp, act)
	}

	// Ensure Retry-After header was set.
	if exp, act := "5", rec.Header().Get("Retry-After"); exp != act {
		t.Fatalf("expected Retry-After header %s, got %s", exp, act)
	}
}
