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
	// Ensure no limit is set for this test.
	prev := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(prev)

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
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
