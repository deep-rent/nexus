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

package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/router"
)

// testThrottle builds a throttle with a controllable clock. The allowance is
// small so that lockout is reached in a few attempts.
func testThrottle(now *time.Time) *Throttle {
	return NewThrottle(ThrottleConfig{
		Rate:    rate.Limit(1),
		Burst:   10,
		Penalty: 5,
		Clock:   func() time.Time { return *now },
	})
}

func TestNewThrottleValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  ThrottleConfig
	}{
		{name: "negative rate", cfg: ThrottleConfig{Rate: -1}},
		{name: "negative burst", cfg: ThrottleConfig{Burst: -1}},
		{
			name: "penalty exceeds burst",
			cfg:  ThrottleConfig{Burst: 5, Penalty: 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("should have panicked on invalid configuration")
				}
			}()
			NewThrottle(tt.cfg)
		})
	}

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()

		th := NewThrottle(ThrottleConfig{})
		if th.rate != DefaultThrottleRate {
			t.Errorf("got rate %v; want %v", th.rate, DefaultThrottleRate)
		}
		if th.burst != DefaultThrottleBurst {
			t.Errorf("got burst %d; want %d", th.burst, DefaultThrottleBurst)
		}
		if th.penalty != DefaultThrottlePenalty {
			t.Errorf(
				"got penalty %d; want %d",
				th.penalty,
				DefaultThrottlePenalty,
			)
		}
	})
}

func TestThrottlePenalize(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	// A fresh key is never blocked.
	if blocked, _ := th.Blocked("k"); blocked {
		t.Fatal("a fresh key should not be blocked")
	}

	// Burst 10 with penalty 5 tolerates two failures before lockout.
	th.Penalize("k")
	if blocked, _ := th.Blocked("k"); blocked {
		t.Fatal("one failure should not exhaust the allowance")
	}

	th.Penalize("k")
	blocked, wait := th.Blocked("k")
	if !blocked {
		t.Fatal("two failures should exhaust the allowance")
	}
	if wait <= 0 {
		t.Errorf("got wait %v; want a positive duration", wait)
	}

	// Each further failure extends the lockout: the deficit grows, so the
	// wait must increase.
	th.Penalize("k")
	_, longer := th.Blocked("k")
	if longer <= wait {
		t.Errorf("got wait %v; want more than %v after another failure", longer, wait)
	}

	// The allowance recovers at the configured rate.
	now = now.Add(longer)
	if blocked, _ := th.Blocked("k"); blocked {
		t.Error("the allowance should have recovered after the wait")
	}
}

func TestThrottleReset(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	th.Penalize("k")
	th.Penalize("k")
	if blocked, _ := th.Blocked("k"); !blocked {
		t.Fatal("the key should be blocked")
	}

	th.Reset("k")
	if blocked, _ := th.Blocked("k"); blocked {
		t.Error("a reset key should not be blocked")
	}
}

func TestThrottleKeysAreIndependent(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	th := testThrottle(&now)

	th.Penalize("a")
	th.Penalize("a")
	if blocked, _ := th.Blocked("a"); !blocked {
		t.Fatal("key a should be blocked")
	}
	if blocked, _ := th.Blocked("b"); blocked {
		t.Error("key b should be unaffected by penalties against key a")
	}
}

func TestThrottleSweep(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)

	// At one token per ten seconds, a single penalty is repaid within the
	// sweep interval while a double penalty is not.
	th := NewThrottle(ThrottleConfig{
		Rate:    rate.Limit(0.1),
		Burst:   10,
		Penalty: 5,
		Clock:   func() time.Time { return now },
	})

	// A recovered bucket is evicted; a penalized one is retained so that
	// its outstanding lockout is not silently dropped.
	th.Penalize("recovered")
	th.Penalize("penalized")
	th.Penalize("penalized")

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

func TestThrottleMiddleware(t *testing.T) {
	t.Parallel()

	// The middleware drives the limiter with the wall clock, so use a
	// generous burst and a rate slow enough that no token refills mid-test.
	th := NewThrottle(ThrottleConfig{
		Rate:    rate.Limit(0.01),
		Burst:   3,
		Penalty: 1,
	})

	r := router.New()
	r.HandleFunc("POST /guarded", func(e *router.Exchange) error {
		e.NoContent()
		return nil
	}, th.Middleware())

	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/guarded", nil)
		req.RemoteAddr = "203.0.113.7:44321"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := range 3 {
		if got := call(); got != http.StatusNoContent {
			t.Fatalf("request %d: got status %d; want %d", i, got, http.StatusNoContent)
		}
	}

	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("got status %d; want %d", got, http.StatusTooManyRequests)
	}

	// A different address carries its own allowance.
	req := httptest.NewRequest(http.MethodPost, "/guarded", nil)
	req.RemoteAddr = "203.0.113.8:44321"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("got status %d; want %d for a fresh address", w.Code, http.StatusNoContent)
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
