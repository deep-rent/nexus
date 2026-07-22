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

package shed

import (
	"math"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/router"
)

// newExchange builds a throwaway exchange for driving the middleware.
func newExchange() *router.Exchange {
	return &router.Exchange{
		R: httptest.NewRequest(http.MethodGet, "/", nil),
		W: router.NewResponseWriter(httptest.NewRecorder()),
	}
}

func TestNew_NoLimit(t *testing.T) {
	t.Parallel()
	// Ensure no limit is set for this test.
	prev := debug.SetMemoryLimit(math.MaxInt64)
	defer func() {
		_ = debug.SetMemoryLimit(prev)
	}()

	// With no memory limit, the factory returns nil so that router.Chain
	// skips it entirely rather than adding an idle layer.
	if mw := New(); mw != nil {
		t.Fatal("expected nil middleware when no limit is set")
	}
}

func TestNew_Overloaded(t *testing.T) {
	t.Parallel()

	// Set a very small memory limit (1000 bytes) for testing.
	prev := debug.SetMemoryLimit(1000)
	defer func() {
		_ = debug.SetMemoryLimit(prev)
	}()

	// Fake the memory provider to report 950 bytes in use (95% of 1000).
	mw := New(
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

	var res *router.Error
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	res, ok := err.(*router.Error)
	if !ok {
		t.Fatalf("expected *router.Error, got %T: %v", err, err)
	}

	if exp, act := http.StatusServiceUnavailable, res.Status; exp != act {
		t.Fatalf("expected status %d, got %d", exp, act)
	}
	if exp, act := ReasonOverload, res.Reason; exp != act {
		t.Fatalf("expected reason %s, got %s", exp, act)
	}

	if exp, act := "5", rec.Header().Get("Retry-After"); exp != act {
		t.Fatalf("expected Retry-After header %s, got %s", exp, act)
	}
}

func TestNew_Recovers(t *testing.T) {
	t.Parallel()
	prev := debug.SetMemoryLimit(1000) // threshold at 0.90 => 900
	defer func() { _ = debug.SetMemoryLimit(prev) }()

	now := time.Unix(1_700_000_000, 0)
	var mem uint64 = 950 // above the threshold
	mw := New(
		WithInterval(time.Second),
		WithClock(func() time.Time { return now }),
		WithMemoryProvider(func() uint64 { return mem }),
	)
	handler := mw(router.HandlerFunc(func(e *router.Exchange) error {
		e.W.WriteHeader(http.StatusOK)
		return nil
	}))
	serve := func() error { return handler.ServeHTTP(newExchange()) }

	// The first request samples an overloaded reading and sheds load.
	if serve() == nil {
		t.Fatal("expected the server to shed load while over the threshold")
	}

	// Memory drops, but within the same interval the verdict is not resampled.
	mem = 100
	if serve() == nil {
		t.Error("verdict should not be resampled within the interval")
	}

	// Past the interval, the fresh reading lifts the load-shedding.
	now = now.Add(2 * time.Second)
	if err := serve(); err != nil {
		t.Errorf("expected recovery once memory dropped, got %v", err)
	}
}

func TestNew_ConcurrentSampling(t *testing.T) {
	t.Parallel()
	prev := debug.SetMemoryLimit(1000)
	defer func() { _ = debug.SetMemoryLimit(prev) }()

	// A fixed clock makes every goroutine race to claim the single sampling
	// slot; the memory reading stays below the threshold. Run under -race to
	// exercise the atomic sample gate.
	now := time.Unix(1_700_000_000, 0)
	mw := New(
		WithClock(func() time.Time { return now }),
		WithMemoryProvider(func() uint64 { return 100 }),
	)
	handler := mw(router.HandlerFunc(func(e *router.Exchange) error {
		e.W.WriteHeader(http.StatusOK)
		return nil
	}))

	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := handler.ServeHTTP(newExchange()); err != nil {
				t.Errorf("unexpected load shedding below threshold: %v", err)
			}
		}()
	}
	wg.Wait()
}
