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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/retry"
)

// tripFunc adapts a function to the [http.RoundTripper] interface.
type tripFunc func(r *http.Request) (*http.Response, error)

func (f tripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// body is a response body that records whether it was closed and how much of
// it was read.
type body struct {
	r      io.Reader
	mu     sync.Mutex
	read   int
	closed bool
}

func newBody(content string) *body {
	return &body{r: strings.NewReader(content)}
}

func (b *body) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.mu.Lock()
	b.read += n
	b.mu.Unlock()
	return n, err
}

func (b *body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *body) stats() (read int, closed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.read, b.closed
}

// respond builds a response carrying the given status and body.
func respond(status int, b io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       b,
	}
}

// counter counts round trips and replies with the given status.
func counter(status int, calls *int) tripFunc {
	var mu sync.Mutex
	return func(*http.Request) (*http.Response, error) {
		mu.Lock()
		*calls++
		mu.Unlock()
		return respond(status, newBody("failure")), nil
	}
}

// netError is a [net.Error] with a configurable timeout flag.
type netError struct{ timeout bool }

func (e *netError) Error() string   { return "net error" }
func (e *netError) Timeout() bool   { return e.timeout }
func (e *netError) Temporary() bool { return false }

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

			req, err := http.NewRequest(tt.method, "http://example.com", nil)
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}

			a := retry.Attempt{Request: req}
			if got := a.Idempotent(); got != tt.want {
				t.Errorf("got %t; want %t", got, tt.want)
			}
		})
	}
}

func TestAttempt_Temporary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *http.Response
		want bool
	}{
		{"no response", nil, false},
		{"408", &http.Response{StatusCode: 408}, true},
		{"429", &http.Response{StatusCode: 429}, true},
		{"500", &http.Response{StatusCode: 500}, true},
		{"502", &http.Response{StatusCode: 502}, true},
		{"503", &http.Response{StatusCode: 503}, true},
		{"504", &http.Response{StatusCode: 504}, true},
		{"200", &http.Response{StatusCode: 200}, false},
		{"400", &http.Response{StatusCode: 400}, false},
		{"501", &http.Response{StatusCode: 501}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := retry.Attempt{Response: tt.res}
			if got := a.Temporary(); got != tt.want {
				t.Errorf("got %t; want %t", got, tt.want)
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
		{"no error", nil, false},
		{"canceled", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped cancellation", wrap(context.Canceled), false},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"EOF", io.EOF, true},
		{"network timeout", &netError{timeout: true}, true},
		{"network error", &netError{timeout: false}, false},
		{"other", errors.New("boom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := retry.Attempt{Error: tt.err}
			if got := a.Transient(); got != tt.want {
				t.Errorf("got %t; want %t", got, tt.want)
			}
		})
	}
}

// wrap wraps the given error so that only [errors.Is] can unwrap it.
func wrap(err error) error {
	return errors.Join(errors.New("context"), err)
}

func TestDefaultPolicy(t *testing.T) {
	t.Parallel()

	get, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	post, err := http.NewRequest(http.MethodPost, "http://example.com", nil)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	tests := []struct {
		name string
		a    retry.Attempt
		want bool
	}{
		{
			"idempotent and temporary",
			retry.Attempt{
				Request:  get,
				Response: &http.Response{StatusCode: 503},
			},
			true,
		},
		{
			"idempotent and transient",
			retry.Attempt{Request: get, Error: &netError{timeout: true}},
			true,
		},
		{
			"idempotent and successful",
			retry.Attempt{
				Request:  get,
				Response: &http.Response{StatusCode: 200},
			},
			false,
		},
		{
			"not idempotent",
			retry.Attempt{
				Request:  post,
				Response: &http.Response{StatusCode: 503},
			},
			false,
		},
		{
			"canceled",
			retry.Attempt{Request: get, Error: context.Canceled},
			false,
		},
	}

	policy := retry.DefaultPolicy()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := policy(tt.a); got != tt.want {
				t.Errorf("got %t; want %t", got, tt.want)
			}
		})
	}
}

func TestPolicy_LimitAttempts(t *testing.T) {
	t.Parallel()

	always := retry.Policy(func(retry.Attempt) bool { return true })

	tests := []struct {
		name  string
		limit int
		count int
		want  bool
	}{
		{"below limit", 3, 2, true},
		{"at limit", 3, 3, false},
		{"above limit", 3, 4, false},
		{"limit of one", 1, 1, false},
		{"no limit", 0, 100, true},
		{"negative limit", -1, 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := always.LimitAttempts(tt.limit)
			got := policy(retry.Attempt{Count: tt.count})

			if got != tt.want {
				t.Errorf("got %t; want %t", got, tt.want)
			}
		})
	}
}

func TestRoundTrip_Success(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(tripFunc(func(*http.Request) (
		*http.Response, error,
	) {
		calls++
		return respond(http.StatusOK, newBody("ok")), nil
	}))

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}

	// The response handed to the caller must still be readable.
	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: should not have returned an error: %v", err)
	}

	if got := string(content); got != "ok" {
		t.Errorf("body: got %q; want %q", got, "ok")
	}
}

func TestRoundTrip_RetriesUntilSuccess(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(tripFunc(func(*http.Request) (
		*http.Response, error,
	) {
		calls++
		if calls < 3 {
			return respond(http.StatusServiceUnavailable, newBody("nope")), nil
		}
		return respond(http.StatusOK, newBody("ok")), nil
	}))

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if calls != 3 {
		t.Errorf("calls: got %d; want 3", calls)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("status: got %d; want %d", res.StatusCode, http.StatusOK)
	}
}

func TestRoundTrip_AttemptLimit(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithAttemptLimit(3),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if calls != 3 {
		t.Errorf("calls: got %d; want 3", calls)
	}
}

// The final response must reach the caller with its body untouched, even
// though earlier bodies were drained.
func TestRoundTrip_PreservesFinalBody(t *testing.T) {
	t.Parallel()

	var (
		calls    int
		drained  []*body
		lastBody *body
	)

	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			b := newBody("payload")
			if calls < 3 {
				drained = append(drained, b)
				return respond(http.StatusServiceUnavailable, b), nil
			}
			lastBody = b
			return respond(http.StatusOK, b), nil
		}),
		retry.WithAttemptLimit(5),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	for i, b := range drained {
		read, closed := b.stats()
		if read == 0 {
			t.Errorf("abandoned body %d: not drained", i)
		}
		if !closed {
			t.Errorf("abandoned body %d: not closed", i)
		}
	}

	if _, closed := lastBody.stats(); closed {
		t.Error("final body: got closed; want open")
	}

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: should not have returned an error: %v", err)
	}

	if got := string(content); got != "payload" {
		t.Errorf("body: got %q; want %q", got, "payload")
	}
}

// An oversized body is closed rather than drained in full.
func TestRoundTrip_BoundsDrain(t *testing.T) {
	t.Parallel()

	const limit = 16

	var (
		calls int
		first *body
	)

	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				first = newBody(strings.Repeat("x", 1024))
				return respond(http.StatusServiceUnavailable, first), nil
			}
			return respond(http.StatusOK, newBody("ok")), nil
		}),
		retry.WithMaxDrainBytes(limit),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	read, closed := first.stats()
	if int64(read) > limit+1 {
		t.Errorf("drained: got %d bytes; want at most %d", read, limit+1)
	}

	if !closed {
		t.Error("abandoned body: not closed")
	}
}

// The caller's request must never be modified, and every attempt must carry a
// complete copy of the body.
func TestRoundTrip_DoesNotMutateRequest(t *testing.T) {
	t.Parallel()

	const payload = "the-payload"

	var (
		calls  int
		bodies []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter, r *http.Request,
	) {
		calls++
		content, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(content))
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	tr := retry.NewTransport(
		http.DefaultTransport,
		retry.WithAttemptLimit(3),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodPut, srv.URL, strings.NewReader(payload),
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	original := *req
	originalBody := req.Body

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if req.Body != originalBody {
		t.Error("caller's request body was replaced")
	}

	if req.URL != original.URL || req.Method != original.Method {
		t.Error("caller's request was modified")
	}

	if calls != 3 {
		t.Fatalf("calls: got %d; want 3", calls)
	}

	for i, got := range bodies {
		if got != payload {
			t.Errorf("attempt %d body: got %q; want %q", i+1, got, payload)
		}
	}
}

// A body that cannot be rewound makes the request unrepeatable, no matter what
// the policy says.
func TestRoundTrip_NonRewindableBody(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithPolicy(func(retry.Attempt) bool { return true }),
		retry.WithAttemptLimit(5),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodPut, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	// A bare reader gives net/http nothing to rewind from.
	req.Body = io.NopCloser(strings.NewReader("payload"))
	req.GetBody = nil

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}
}

func TestRoundTrip_RespectsRetryAfter(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			res := respond(http.StatusTooManyRequests, newBody("slow down"))
			if calls == 1 {
				res.Header.Set("Retry-After", "1")
			}
			return res, nil
		}),
		retry.WithAttemptLimit(2),
	)

	// The context deadline is shorter than the delay the server asks for, so
	// the transport must give up instead of waiting.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	start := time.Now()
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("elapsed: got %v; want an immediate return", elapsed)
	}

	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}

	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status: got %d; want 429", res.StatusCode)
	}
}

func TestRoundTrip_StopsWhenDeadlineWouldElapse(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithBackoff(backoff.Constant(time.Hour)),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}

	// The caller receives a usable response rather than a context error.
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d; want 503", res.StatusCode)
	}
}

func TestRoundTrip_ContextCanceledDuringBackoff(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithBackoff(backoff.Constant(time.Hour)),
	)

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := tr.RoundTrip(req)
		errCh <- err
	}()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v; want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("did not return after cancellation")
	}
}

func TestRoundTrip_ContextAlreadyCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var calls int
	tr := retry.NewTransport(counter(http.StatusOK, &calls))

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if _, err := tr.RoundTrip(req); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v; want %v", err, context.Canceled)
	}

	if calls != 0 {
		t.Errorf("calls: got %d; want 0", calls)
	}
}

func TestRoundTrip_TransportError(t *testing.T) {
	t.Parallel()

	wantErr := &netError{timeout: true}

	var calls int
	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, wantErr
		}),
		retry.WithAttemptLimit(3),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if _, err := tr.RoundTrip(req); !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	if calls != 3 {
		t.Errorf("calls: got %d; want 3", calls)
	}
}

func TestRoundTrip_RewindFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("cannot rewind")

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithAttemptLimit(3),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodPut, "http://example.com",
		strings.NewReader("payload"),
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	req.GetBody = func() (io.ReadCloser, error) { return nil, wantErr }

	if _, err := tr.RoundTrip(req); !errors.Is(err, wantErr) {
		t.Errorf("error: got %v; want %v", err, wantErr)
	}

	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}
}

// Concurrent requests must not inflate each other's backoff. With shared
// attempt state, the delays escalate to the maximum within a few requests.
func TestRoundTrip_ConcurrentRequestsBackOffIndependently(t *testing.T) {
	t.Parallel()

	const (
		requests = 8
		attempts = 3
		step     = 10 * time.Millisecond
	)

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithAttemptLimit(attempts),
		retry.WithBackoff(backoff.Exponential(step, time.Minute, 2)),
	)

	// Each request waits step + 2*step between its three attempts.
	want := step + 2*step

	var wg sync.WaitGroup
	start := time.Now()

	for range requests {
		wg.Go(func() {

			req, err := http.NewRequestWithContext(
				t.Context(), http.MethodGet, "http://example.com", nil,
			)
			if err != nil {
				t.Errorf("should not have returned an error: %v", err)
				return
			}

			res, err := tr.RoundTrip(req)
			if err != nil {
				t.Errorf("should not have returned an error: %v", err)
				return
			}
			res.Body.Close()
		})
	}
	wg.Wait()

	// Generous headroom for scheduling; the point is that the total stays
	// proportional to a single request's schedule, not to the request count.
	if elapsed := time.Since(start); elapsed > 4*want {
		t.Errorf(
			"elapsed: got %v; want roughly %v (shared backoff state?)",
			elapsed, want,
		)
	}
}

func TestRoundTrip_LogsAttempts(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	var calls int
	tr := retry.NewTransport(
		counter(http.StatusServiceUnavailable, &calls),
		retry.WithAttemptLimit(2),
		retry.WithLogger(logger),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	logs := buf.String()
	tests := []struct {
		name string
		want string
	}{
		{"message", "Request attempt failed, retrying"},
		{"attempt", "attempt=1"},
		{"status", "status=503"},
		{"method", "method=GET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(logs, tt.want) {
				t.Errorf("want match for %q; got %q", tt.want, logs)
			}
		})
	}
}

func TestRoundTrip_LogsTransportError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			return nil, &netError{timeout: true}
		}),
		retry.WithAttemptLimit(2),
		retry.WithLogger(logger),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("should have returned an error")
	}

	if want := "error="; !strings.Contains(buf.String(), want) {
		t.Errorf("want match for %q; got %q", want, buf.String())
	}
}

// Draining can be turned off entirely, in which case the body is closed
// without being read.
func TestRoundTrip_DrainDisabled(t *testing.T) {
	t.Parallel()

	var (
		calls int
		first *body
	)

	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				first = newBody("failure")
				return respond(http.StatusServiceUnavailable, first), nil
			}
			return respond(http.StatusOK, newBody("ok")), nil
		}),
		retry.WithMaxDrainBytes(0),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	read, closed := first.stats()
	if read != 0 {
		t.Errorf("drained: got %d bytes; want 0", read)
	}

	if !closed {
		t.Error("abandoned body: not closed")
	}
}

// A body that fails to drain or close must not derail the retry loop.
func TestRoundTrip_ToleratesBrokenBody(t *testing.T) {
	t.Parallel()

	var calls int
	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return respond(http.StatusServiceUnavailable, brokenBody{}), nil
			}
			return respond(http.StatusOK, newBody("ok")), nil
		}),
		retry.WithAttemptLimit(3),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("status: got %d; want 200", res.StatusCode)
	}
}

// brokenBody fails on every operation.
type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (brokenBody) Close() error { return errors.New("close failed") }

func TestWithClock(t *testing.T) {
	t.Parallel()

	// A Retry-After date is interpreted against the injected clock, which
	// places it one hour in the future.
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)

	var calls int
	tr := retry.NewTransport(
		tripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			res := respond(http.StatusTooManyRequests, newBody("slow down"))
			res.Header.Set(
				"Retry-After",
				now.Add(time.Hour).Format(http.TimeFormat),
			)
			return res, nil
		}),
		retry.WithClock(func() time.Time { return now }),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer res.Body.Close()

	// The hour-long delay exceeds the deadline, so no retry is attempted.
	if calls != 1 {
		t.Errorf("calls: got %d; want 1", calls)
	}
}
