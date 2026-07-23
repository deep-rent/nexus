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

package throttle

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/net/router"
)

// penalty is the charge used by the tests that exercise [Throttle.Penalize].
const penalty = 5

// testThrottle builds a throttle with a controllable clock. The allowance is
// small so that lockout is reached in a few penalties of size [penalty].
func testThrottle(now *time.Time) *Throttle {
	return New(Config{
		Rate:  rate.Limit(1),
		Burst: 10,
		Clock: func() time.Time { return *now },
	})
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "negative rate", cfg: Config{Rate: -1}},
		{name: "negative burst", cfg: Config{Burst: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("should have panicked on invalid configuration")
				}
			}()
			New(tt.cfg)
		})
	}

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()

		th := New(Config{})
		if th.rate != DefaultLimit {
			t.Errorf("got rate %v; want %v", th.rate, DefaultLimit)
		}
		if th.burst != DefaultBurst {
			t.Errorf("got burst %d; want %d", th.burst, DefaultBurst)
		}
	})
}

func TestAllow(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := New(Config{
		Rate:  rate.Limit(1),
		Burst: 3,
		Clock: func() time.Time { return now },
	})

	// The burst is spent one token at a time, then the key is blocked.
	for i := range 3 {
		if !th.Allow("k") {
			t.Fatalf("token %d: got blocked; want allowed", i)
		}
	}
	if th.Allow("k") {
		t.Error("a spent bucket should block the next request")
	}

	// The allowance recovers at the configured rate.
	now = now.Add(time.Second)
	if !th.Allow("k") {
		t.Error("a token should have refilled after a second")
	}
}

func TestAllowN(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := New(Config{
		Rate:  rate.Limit(1),
		Burst: 5,
		Clock: func() time.Time { return now },
	})

	// A spend larger than the balance takes nothing and reports failure.
	if th.AllowN("k", 6) {
		t.Error("spending more than the burst should fail")
	}
	if blocked, _ := th.Blocked("k"); blocked {
		t.Error("a failed spend must not consume any allowance")
	}

	// A spend within the balance succeeds.
	if !th.AllowN("k", 5) {
		t.Error("spending the full burst should succeed")
	}
	if th.AllowN("k", 1) {
		t.Error("the bucket should be empty after spending the burst")
	}

	// A non-positive spend is a no-op that always succeeds.
	if !th.AllowN("k", 0) {
		t.Error("spending zero should always succeed")
	}
}

func TestPenalize(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	// A fresh key is never blocked.
	if blocked, _ := th.Blocked("k"); blocked {
		t.Fatal("a fresh key should not be blocked")
	}

	// Burst 10 with penalty 5 tolerates two failures before lockout.
	th.Penalize("k", penalty)
	if blocked, _ := th.Blocked("k"); blocked {
		t.Fatal("one failure should not exhaust the allowance")
	}

	th.Penalize("k", penalty)
	blocked, wait := th.Blocked("k")
	if !blocked {
		t.Fatal("two failures should exhaust the allowance")
	}
	if wait <= 0 {
		t.Errorf("got wait %v; want a positive duration", wait)
	}

	// Each further failure extends the lockout: the deficit grows, so the
	// wait must increase.
	th.Penalize("k", penalty)
	_, longer := th.Blocked("k")
	if longer <= wait {
		t.Errorf(
			"got wait %v; want more than %v after another failure",
			longer,
			wait,
		)
	}

	// The allowance recovers at the configured rate.
	now = now.Add(longer)
	if blocked, _ := th.Blocked("k"); blocked {
		t.Error("the allowance should have recovered after the wait")
	}
}

// A charge is clamped to the burst, so a bucket cannot be driven more than one
// full burst into deficit at once.
func TestPenalize_ClampsToBurst(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := New(Config{
		Rate:  rate.Limit(1),
		Burst: 4,
		Clock: func() time.Time { return now },
	})

	th.Penalize("k", 1000)
	_, wait := th.Blocked("k")

	// A full-burst deficit against a drained bucket needs Burst seconds at one
	// token per second, not a thousand.
	if want := 4 * time.Second; wait > want {
		t.Errorf(
			"got wait %v; want at most %v (charge was not clamped)",
			wait,
			want,
		)
	}
}

// A non-positive charge does nothing.
func TestPenalize_NonPositive(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	th.Penalize("k", 0)
	th.Penalize("k", -5)

	if blocked, _ := th.Blocked("k"); blocked {
		t.Error("a non-positive charge should not affect the bucket")
	}
}

func TestReset(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	th.Penalize("k", penalty)
	th.Penalize("k", penalty)
	if blocked, _ := th.Blocked("k"); !blocked {
		t.Fatal("the key should be blocked")
	}

	th.Reset("k")
	if blocked, _ := th.Blocked("k"); blocked {
		t.Error("a reset key should not be blocked")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	th.Penalize("a", penalty)
	th.Penalize("a", penalty)
	if blocked, _ := th.Blocked("a"); !blocked {
		t.Fatal("key a should be blocked")
	}
	if blocked, _ := th.Blocked("b"); blocked {
		t.Error("key b should be unaffected by penalties against key a")
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)

	// At one token per ten seconds, a single penalty is repaid within the
	// sweep interval while a double penalty is not.
	th := New(Config{
		Rate:  rate.Limit(0.1),
		Burst: 10,
		Clock: func() time.Time { return now },
	})

	// A recovered bucket is evicted; a penalized one is retained so that its
	// outstanding lockout is not silently dropped.
	th.Penalize("recovered", penalty)
	th.Penalize("penalized", penalty)
	th.Penalize("penalized", penalty)

	// Let "recovered" refill completely, then trigger a sweep.
	now = now.Add(sweepInterval)
	th.Blocked("trigger")

	th.mu.Lock()
	_, keptRecovered := th.buckets["recovered"]
	_, keptPenalized := th.buckets["penalized"]
	th.mu.Unlock()

	if keptRecovered {
		t.Error("a fully recovered bucket should have been evicted")
	}
	if !keptPenalized {
		t.Error("a bucket still in deficit should have been retained")
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	// The middleware drives the limiter with the wall clock, so use a generous
	// burst and a rate slow enough that no token refills mid-test.
	th := New(Config{
		Rate:  rate.Limit(0.01),
		Burst: 3,
	})

	r := router.New()
	r.HandleFunc("POST /guarded", func(e *router.Exchange) error {
		e.NoContent()
		return nil
	}, th.Middleware())

	call := func(addr string) int {
		req := httptest.NewRequest(http.MethodPost, "/guarded", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := range 3 {
		if got := call("203.0.113.7:44321"); got != http.StatusNoContent {
			t.Fatalf("request %d: got status %d; want %d",
				i, got, http.StatusNoContent)
		}
	}

	if got := call("203.0.113.7:44321"); got != http.StatusTooManyRequests {
		t.Fatalf("got status %d; want %d", got, http.StatusTooManyRequests)
	}

	// A different address carries its own allowance.
	if got := call("203.0.113.8:44321"); got != http.StatusNoContent {
		t.Errorf("got status %d; want %d for a fresh address",
			got, http.StatusNoContent)
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wait time.Duration
		want string
	}{
		{"whole second", 3 * time.Second, "3"},
		{"rounds up", 1500 * time.Millisecond, "2"},
		{"sub-second rounds to one", 10 * time.Millisecond, "1"},
		{"zero writes nothing", 0, ""},
		{"negative writes nothing", -time.Second, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{}
			RetryAfter(h, tt.wait)
			if got := h.Get("Retry-After"); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "host and port", addr: "203.0.113.7:44321", want: "203.0.113.7"},
		{
			name: "ipv6",
			addr: "[2001:db8::1]:44321",
			want: "2001:db8::1",
		},
		{name: "bare host", addr: "203.0.113.7", want: "203.0.113.7"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.addr
			if got := RemoteAddr(r); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}
