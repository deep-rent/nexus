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

package retry_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/retry"
)

type mockTrip struct {
	res *http.Response
	err error
}

type mockRoundTripper struct {
	mu    sync.Mutex
	trips []mockTrip
	calls int
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++
	if len(m.trips) >= m.calls {
		trip := m.trips[m.calls-1]
		return trip.res, trip.err
	}
	return nil, fmt.Errorf(
		"not enough trips mocked: have %d, need %d", len(m.trips), m.calls,
	)
}

func (m *mockRoundTripper) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

var _ http.RoundTripper = (*mockRoundTripper)(nil)

func mockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

type mockError struct{ isTimeout bool }

func (e *mockError) Error() string   { return "net error" }
func (e *mockError) Timeout() bool   { return e.isTimeout }
func (e *mockError) Temporary() bool { return false }

var _ net.Error = (*mockError)(nil)

type mockBackoff struct {
	next func() time.Duration
	done func()
}

func (m *mockBackoff) Next() time.Duration {
	if m.next != nil {
		return m.next()
	}
	return 0
}

func (m *mockBackoff) Done() {
	if m.done != nil {
		m.done()
	}
}
func (m *mockBackoff) MinDelay() time.Duration { return 0 }
func (m *mockBackoff) MaxDelay() time.Duration { return 0 }

var _ backoff.Strategy = (*mockBackoff)(nil)

func TestAttempt_Idempotent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodOptions, true},
		{http.MethodTrace, true},
		{http.MethodPut, true},
		{http.MethodDelete, true},
		{http.MethodPost, false},
		{http.MethodPatch, false},
		{http.MethodConnect, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequest(tt.method, "/", nil)
			a := retry.Attempt{Request: req}
			if got := a.Idempotent(); got != tt.want {
				t.Errorf("Attempt.Idempotent() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestAttempt_Temporary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		want   bool
	}{
		{http.StatusRequestTimeout, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
		{http.StatusOK, false},
		{http.StatusBadRequest, false},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			t.Parallel()
			a := retry.Attempt{Response: &http.Response{StatusCode: tt.status}}
			if got := a.Temporary(); got != tt.want {
				t.Errorf("Attempt.Temporary() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestAttempt_Transient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline exceeded", context.DeadlineExceeded, false},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"EOF", io.EOF, true},
		{"net timeout error", &mockError{isTimeout: true}, true},
		{"net non-timeout error", &mockError{isTimeout: false}, false},
		{"other error", errors.New("other"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := retry.Attempt{Error: tt.err}
			if got := a.Transient(); got != tt.want {
				t.Errorf("Attempt.Transient() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		attempt retry.Attempt
		want    bool
	}{
		{
			name: "idempotent and temporary",
			attempt: retry.Attempt{
				Request:  &http.Request{Method: http.MethodGet},
				Response: &http.Response{StatusCode: http.StatusServiceUnavailable},
			},
			want: true,
		},
		{
			name: "idempotent and transient",
			attempt: retry.Attempt{
				Request: &http.Request{Method: http.MethodGet},
				Error:   &mockError{isTimeout: true},
			},
			want: true,
		},
		{
			name: "non-idempotent",
			attempt: retry.Attempt{
				Request:  &http.Request{Method: http.MethodPost},
				Response: &http.Response{StatusCode: http.StatusServiceUnavailable},
			},
			want: false,
		},
		{
			name: "permanent error",
			attempt: retry.Attempt{
				Request:  &http.Request{Method: http.MethodGet},
				Response: &http.Response{StatusCode: http.StatusBadRequest},
			},
			want: false,
		},
	}

	policy := retry.DefaultPolicy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := policy(tt.attempt); got != tt.want {
				t.Errorf("DefaultPolicy(attempt) = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestPolicy_LimitAttempts(t *testing.T) {
	t.Parallel()

	always := func(retry.Attempt) bool { return true }

	t.Run("limit positive", func(t *testing.T) {
		t.Parallel()
		limited := retry.Policy(always).LimitAttempts(3)
		if !limited(retry.Attempt{Count: 1}) {
			t.Error("attempt 1 should pass")
		}
		if !limited(retry.Attempt{Count: 2}) {
			t.Error("attempt 2 should pass")
		}
		if limited(retry.Attempt{Count: 3}) {
			t.Error("attempt 3 should fail")
		}
	})

	t.Run("limit zero", func(t *testing.T) {
		t.Parallel()
		unlimited := retry.Policy(always).LimitAttempts(0)
		if !unlimited(retry.Attempt{Count: 99}) {
			t.Error("attempt 99 should pass when limit is 0")
		}
	})
}

func TestTransport_RoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("success on first try", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{trips: []mockTrip{
			{res: mockResponse(http.StatusOK, "ok")},
		}}
		transport := retry.NewTransport(m)
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
		if got, want := m.Calls(), 1; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("retry on temporary error", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: mockResponse(http.StatusServiceUnavailable, "fail")},
				{res: mockResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(m, retry.WithAttemptLimit(3))
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
		if got, want := m.Calls(), 2; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("retry on transient error", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{err: &mockError{isTimeout: true}},
				{res: mockResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(m, retry.WithAttemptLimit(3))
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
		if got, want := m.Calls(), 2; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("fails after limit reached", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: mockResponse(http.StatusServiceUnavailable, "fail1")},
				{res: mockResponse(http.StatusServiceUnavailable, "fail2")},
				{res: mockResponse(http.StatusServiceUnavailable, "fail3")},
			},
		}
		transport := retry.NewTransport(m, retry.WithAttemptLimit(2))
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusServiceUnavailable; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
		if got, want := m.Calls(), 2; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("context cancellation stops retries", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: mockResponse(http.StatusServiceUnavailable, "fail")},
			},
		}
		transport := retry.NewTransport(m, retry.WithBackoff(
			backoff.Constant(100*time.Millisecond),
		))
		ctx, cancel := context.WithCancel(t.Context())
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		_, err := transport.RoundTrip(req)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("RoundTrip() err = %v; want %v", err, context.Canceled)
		}
		if got, want := m.Calls(), 1; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("non-rewindable body prevents retry", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: mockResponse(http.StatusServiceUnavailable, "fail")},
			},
		}
		transport := retry.NewTransport(m)
		req, _ := http.NewRequest("PUT", "/", http.NoBody)
		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusServiceUnavailable; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
		if got, want := m.Calls(), 1; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("rewindable body allows retry", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: mockResponse(http.StatusServiceUnavailable, "fail")},
				{res: mockResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(m)
		body := "body"
		req, _ := http.NewRequest("PUT", "/", strings.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}
		if got, want := res.StatusCode, http.StatusOK; got != want {
			t.Errorf("res.StatusCode = %d; want %d", got, want)
		}
		if got, want := m.Calls(), 2; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("respects retry-after header", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		resp := mockResponse(http.StatusTooManyRequests, "rate limited")
		resp.Header.Set("Retry-After", "1")

		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: resp},
				{res: mockResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(m,
			retry.WithBackoff(backoff.Constant(100*time.Millisecond)),
			retry.WithClock(func() time.Time { return now }),
		)
		req, _ := http.NewRequest("GET", "/", nil)

		start := time.Now()
		_, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}

		if d := time.Since(start); d < time.Second {
			t.Errorf("time.Since(start) = %v; want >= 1s", d)
		}
		if got, want := m.Calls(), 2; got != want {
			t.Errorf("m.Calls() = %d; want %d", got, want)
		}
	})

	t.Run("custom options are used", func(t *testing.T) {
		t.Parallel()
		m := &mockRoundTripper{
			trips: []mockTrip{
				{res: mockResponse(http.StatusOK, "ok")},
			},
		}
		var seen, seenBackoff bool
		transport := retry.NewTransport(m,
			retry.WithPolicy(func(retry.Attempt) bool {
				seen = true
				return false
			}),
			retry.WithBackoff(&mockBackoff{
				next: func() time.Duration {
					seenBackoff = true
					return 0
				},
			}),
			retry.WithAttemptLimit(5),
		)

		req, _ := http.NewRequest("GET", "/", nil)
		_, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip() err = %v", err)
		}

		if !seen {
			t.Error("policy was not called")
		}
		if seenBackoff {
			t.Error("backoff should not have advanced for a successful call")
		}
	})
}
