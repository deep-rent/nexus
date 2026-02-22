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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newResponse(statusCode int, body string) *http.Response {
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

func TestAttempt(t *testing.T) {
	t.Run("Idempotent", func(t *testing.T) {
		type test struct {
			method string
			want   bool
		}
		tests := []test{
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
		for _, tc := range tests {
			t.Run(tc.method, func(t *testing.T) {
				req, _ := http.NewRequest(tc.method, "/", nil)
				a := retry.Attempt{Request: req}
				assert.Equal(t, tc.want, a.Idempotent())
			})
		}
	})

	t.Run("Temporary", func(t *testing.T) {
		type test struct {
			status int
			want   bool
		}
		tests := []test{
			{http.StatusRequestTimeout, true},
			{http.StatusTooManyRequests, true},
			{http.StatusInternalServerError, true},
			{http.StatusBadGateway, true},
			{http.StatusServiceUnavailable, true},
			{http.StatusGatewayTimeout, true},
			{http.StatusOK, false},
			{http.StatusBadRequest, false},
		}
		for _, tc := range tests {
			t.Run(http.StatusText(tc.status), func(t *testing.T) {
				a := retry.Attempt{Response: &http.Response{StatusCode: tc.status}}
				assert.Equal(t, tc.want, a.Temporary())
			})
		}
	})

	t.Run("Transient", func(t *testing.T) {
		type test struct {
			name string
			err  error
			want bool
		}
		tests := []test{
			{"nil error", nil, false},
			{"context canceled", context.Canceled, false},
			{"context deadline exceeded", context.DeadlineExceeded, false},
			{"unexpected EOF", io.ErrUnexpectedEOF, true},
			{"EOF", io.EOF, true},
			{"net timeout error", &mockError{isTimeout: true}, true},
			{"net non-timeout error", &mockError{isTimeout: false}, false},
			{"other error", errors.New("other"), false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				a := retry.Attempt{Error: tc.err}
				assert.Equal(t, tc.want, a.Transient())
			})
		}
	})
}

func TestDefaultPolicy(t *testing.T) {
	type test struct {
		name    string
		attempt retry.Attempt
		want    bool
	}
	tests := []test{
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, policy(tc.attempt))
		})
	}
}

func TestLimitAttempts(t *testing.T) {
	always := func(retry.Attempt) bool { return true }
	limited := retry.Policy(always).LimitAttempts(3)

	assert.True(t, limited(retry.Attempt{Count: 1}), "attempt 1 should pass")
	assert.True(t, limited(retry.Attempt{Count: 2}), "attempt 2 should pass")
	assert.False(t, limited(retry.Attempt{Count: 3}), "attempt 3 should fail")

	unlimited := retry.Policy(always).LimitAttempts(0)
	assert.True(t, unlimited(retry.Attempt{Count: 99}))
}

func TestTransport(t *testing.T) {
	t.Run("success on first try", func(t *testing.T) {
		mock := &mockRoundTripper{trips: []mockTrip{
			{res: newResponse(http.StatusOK, "ok")},
		}}
		transport := retry.NewTransport(mock)
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, 1, mock.Calls())
	})

	t.Run("retry on temporary error", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{
				{res: newResponse(http.StatusServiceUnavailable, "fail")},
				{res: newResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(mock, retry.WithAttemptLimit(3))
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, 2, mock.Calls())
	})

	t.Run("retry on transient error", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{
				{err: &mockError{isTimeout: true}},
				{res: newResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(mock, retry.WithAttemptLimit(3))
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, 2, mock.Calls())
	})

	t.Run("fails after limit reached", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{
				{res: newResponse(http.StatusServiceUnavailable, "fail1")},
				{res: newResponse(http.StatusServiceUnavailable, "fail2")},
				{res: newResponse(http.StatusServiceUnavailable, "fail3")},
			},
		}
		transport := retry.NewTransport(mock, retry.WithAttemptLimit(2))
		req, _ := http.NewRequest("GET", "/", nil)
		res, err := transport.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
		assert.Equal(t, 2, mock.Calls())
	})

	t.Run("context cancellation stops retries", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{
				{res: newResponse(http.StatusServiceUnavailable, "fail")},
			},
		}
		transport := retry.NewTransport(mock, retry.WithBackoff(
			backoff.Constant(100*time.Millisecond),
		))
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		_, err := transport.RoundTrip(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, mock.Calls())
	})

	t.Run("non-rewindable body prevents retry", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{{
				res: newResponse(http.StatusServiceUnavailable, "fail")},
			},
		}
		transport := retry.NewTransport(mock)
		req, _ := http.NewRequest("PUT", "/", http.NoBody)
		res, err := transport.RoundTrip(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
		assert.Equal(t, 1, mock.Calls())
	})

	t.Run("rewindable body allows retry", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{
				{res: newResponse(http.StatusServiceUnavailable, "fail")},
				{res: newResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(mock)
		body := "body"
		req, _ := http.NewRequest("PUT", "/", strings.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
		res, err := transport.RoundTrip(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, 2, mock.Calls())
	})

	t.Run("respects Retry-After header", func(t *testing.T) {
		now := time.Now()
		resp := newResponse(http.StatusTooManyRequests, "rate limited")
		resp.Header.Set("Retry-After", "1")

		mock := &mockRoundTripper{
			trips: []mockTrip{
				{res: resp},
				{res: newResponse(http.StatusOK, "ok")},
			},
		}
		transport := retry.NewTransport(mock,
			retry.WithBackoff(backoff.Constant(100*time.Millisecond)),
			retry.WithClock(func() time.Time { return now }),
		)
		req, _ := http.NewRequest("GET", "/", nil)

		start := time.Now()
		_, err := transport.RoundTrip(req)
		require.NoError(t, err)

		d := time.Since(start)
		assert.GreaterOrEqual(t, d, time.Second, "should wait at least 1 second")
		assert.Equal(t, 2, mock.Calls())
	})

	t.Run("custom options are used", func(t *testing.T) {
		mock := &mockRoundTripper{
			trips: []mockTrip{
				{res: newResponse(http.StatusOK, "ok")},
			},
		}
		var seen, seenBackoff bool
		transport := retry.NewTransport(mock,
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
			retry.WithLogger(slog.New(slog.NewTextHandler(new(bytes.Buffer), nil))),
			retry.WithAttemptLimit(5),
		)

		req, _ := http.NewRequest("GET", "/", nil)
		_, err := transport.RoundTrip(req)
		require.NoError(t, err)

		assert.True(t, seen, "policy should be called")
		assert.False(t, seenBackoff, "backoff should not have advanced")
	})
}
