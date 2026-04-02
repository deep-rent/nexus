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

package cache_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/retry"
	"github.com/deep-rent/nexus/scheduler"
)

type mockRoundTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.roundTrip(r)
}

var _ http.RoundTripper = (*mockRoundTripper)(nil)

type mockResource struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

var mockMapper cache.Mapper[mockResource] = func(
	r *cache.Response,
) (mockResource, error) {
	var res mockResource
	err := json.Unmarshal(r.Body, &res)
	return res, err
}

var mockErrorMapper cache.Mapper[mockResource] = func(
	*cache.Response,
) (mockResource, error) {
	return mockResource{}, errors.New("parsing failed")
}

type mockHandler struct {
	mu        sync.Mutex
	status    int
	reqHeader http.Header
	resHeader http.Header
	body      string
	count     atomic.Int32
	sleep     time.Duration
}

func (h *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.sleep > 0 {
		select {
		case <-time.After(h.sleep):
		case <-r.Context().Done():
			return
		}
	}

	h.count.Add(1)
	h.reqHeader = r.Header.Clone()

	for k, v := range h.resHeader {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(h.status)
	if h.body != "" {
		_, _ = io.WriteString(w, h.body)
	}
}

func (h *mockHandler) Count() int {
	return int(h.count.Load())
}

func (h *mockHandler) RequestHeader(key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reqHeader.Get(key)
}

func TestController_GetAndReady(t *testing.T) {
	t.Parallel()
	h := &mockHandler{
		status: http.StatusOK,
		body:   `{"id":1, "name":"test"}`,
	}
	s := httptest.NewServer(h)
	defer s.Close()

	c := cache.NewController(s.URL, mockMapper)

	_, ok := c.Get()
	if ok {
		t.Errorf("Get() ok = %t; want %t", ok, false)
	}

	select {
	case <-c.Ready():
		t.Fatal("Ready() channel should block before first fetch")
	default:
	}

	d := c.Run(t.Context())
	if d == 0 {
		t.Errorf("Run() delay = %v; want non-zero", d)
	}

	r, ok := c.Get()
	if !ok {
		t.Errorf("Get() ok = %t; want %t", ok, true)
	}
	if got, want := r, (mockResource{ID: 1, Name: "test"}); got != want {
		t.Errorf("Get() resource = %v; want %v", got, want)
	}
	select {
	case <-c.Ready():
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Ready channel should be closed after successful fetch")
	}
}

func TestController_Run(t *testing.T) {
	t.Parallel()
	const (
		minInt = 1 * time.Minute
		maxInt = 1 * time.Hour
	)

	goodResource := mockResource{ID: 42, Name: "success"}
	goodBody, _ := json.Marshal(goodResource)

	tests := []struct {
		name           string
		handler        *mockHandler
		mapper         cache.Mapper[mockResource]
		wantDelay      time.Duration
		wantDelayDelta time.Duration
		wantResource   mockResource
		wantOK         bool
		wantLogs       string
	}{
		{
			name: "success with max-age",
			handler: &mockHandler{
				status:    http.StatusOK,
				body:      string(goodBody),
				resHeader: http.Header{"Cache-Control": {"max-age=120"}},
			},
			mapper:       mockMapper,
			wantDelay:    2 * time.Minute,
			wantResource: goodResource,
			wantOK:       true,
		},
		{
			name: "clamp to min interval",
			handler: &mockHandler{
				status:    http.StatusOK,
				body:      string(goodBody),
				resHeader: http.Header{"Cache-Control": {"max-age=30"}},
			},
			mapper:       mockMapper,
			wantDelay:    minInt,
			wantResource: goodResource,
			wantOK:       true,
		},
		{
			name: "clamp to max interval",
			handler: &mockHandler{
				status:    http.StatusOK,
				body:      string(goodBody),
				resHeader: http.Header{"Cache-Control": {"max-age=7200"}},
			},
			mapper:       mockMapper,
			wantDelay:    maxInt,
			wantResource: goodResource,
			wantOK:       true,
		},
		{
			name: "no-store header",
			handler: &mockHandler{
				status:    http.StatusOK,
				body:      string(goodBody),
				resHeader: http.Header{"Cache-Control": {"no-store"}},
			},
			mapper:       mockMapper,
			wantDelay:    minInt,
			wantResource: goodResource,
			wantOK:       true,
		},
		{
			name: "server error",
			handler: &mockHandler{
				status: http.StatusInternalServerError,
				body:   "error",
			},
			mapper:       mockMapper,
			wantDelay:    minInt,
			wantResource: mockResource{},
			wantOK:       false,
			wantLogs:     "Received a non-retriable HTTP status code",
		},
		{
			name: "mapper error",
			handler: &mockHandler{
				status: http.StatusOK,
				body:   `invalid`,
			},
			mapper:       mockErrorMapper,
			wantDelay:    minInt,
			wantResource: mockResource{},
			wantOK:       false,
			wantLogs:     "Couldn't parse response body",
		},
		{
			name: "body read error",
			handler: &mockHandler{
				status: http.StatusOK,
				body:   "ok",
			},
			mapper:       mockMapper,
			wantDelay:    minInt,
			wantResource: mockResource{},
			wantOK:       false,
			wantLogs:     "Failed to read response body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var s *httptest.Server
			if tt.name == "body read error" {
				s = httptest.NewServer(http.HandlerFunc(func(
					w http.ResponseWriter, _ *http.Request,
				) {
					w.Header().Set("Content-Length", "10")
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, "short")
				}))
			} else {
				s = httptest.NewServer(tt.handler)
			}
			defer s.Close()

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			c := cache.NewController(s.URL, tt.mapper,
				cache.WithMinInterval(minInt),
				cache.WithMaxInterval(maxInt),
				cache.WithLogger(logger),
				cache.WithRetryOptions(retry.WithAttemptLimit(1)),
			)
			d := c.Run(t.Context())

			if tt.wantDelayDelta > 0 {
				diff := math.Abs(float64(tt.wantDelayDelta - d))
				if diff > float64(time.Second) {
					t.Errorf("Run() delay = %v; want %v (delta %v)",
						d, tt.wantDelayDelta, time.Second)
				}
			} else if d != tt.wantDelay {
				t.Errorf("Run() delay = %v; want %v", d, tt.wantDelay)
			}

			res, ok := c.Get()
			if ok != tt.wantOK {
				t.Errorf("Get() ok = %t; want %t", ok, tt.wantOK)
			}
			if res != tt.wantResource {
				t.Errorf("Get() resource = %v; want %v", res, tt.wantResource)
			}

			if tt.wantLogs != "" {
				if got := buf.String(); !strings.Contains(got, tt.wantLogs) {
					t.Errorf("logs = %q; want to contain %q", got, tt.wantLogs)
				}
			}

			if tt.wantOK {
				select {
				case <-c.Ready():
				default:
					t.Error("Ready() channel should be closed on success")
				}
			}
		})
	}
}

func TestController_Run_ConditionalHeaders(t *testing.T) {
	t.Parallel()
	h := &mockHandler{}
	s := httptest.NewServer(h)
	defer s.Close()

	c := cache.NewController(s.URL, mockMapper)

	h.mu.Lock()
	h.status = http.StatusOK
	h.body = `{"id":1}`
	h.resHeader = http.Header{
		"Etag":          {`"v1"`},
		"Last-Modified": {"some-date"},
	}
	h.mu.Unlock()

	const (
		ifNoneMatch     = "If-None-Match"
		ifModifiedSince = "If-Modified-Since"
	)

	c.Run(t.Context())
	if got, want := h.Count(), 1; got != want {
		t.Fatalf("Count() = %d; want %d", got, want)
	}
	if got := h.RequestHeader(ifNoneMatch); len(got) != 0 {
		t.Errorf("RequestHeader(%q) = %q; want empty", ifNoneMatch, got)
	}
	if got := h.RequestHeader(ifModifiedSince); len(got) != 0 {
		t.Errorf("RequestHeader(%q) = %q; want empty", ifModifiedSince, got)
	}

	h.mu.Lock()
	h.status = http.StatusNotModified
	h.body = ""
	h.mu.Unlock()

	c.Run(t.Context())
	if got, want := h.Count(), 2; got != want {
		t.Fatalf("Count() = %d; want %d", got, want)
	}
	if got, want := h.RequestHeader(ifNoneMatch), `"v1"`; got != want {
		t.Errorf("RequestHeader(%q) = %q; want %q", ifNoneMatch, got, want)
	}
	if got, want := h.RequestHeader(ifModifiedSince), "some-date"; got != want {
		t.Errorf("RequestHeader(%q) = %q; want %q", ifModifiedSince, got, want)
	}

	res, ok := c.Get()
	if !ok {
		t.Fatalf("Get() ok = %t; want %t", ok, true)
	}
	if got, want := res.ID, 1; got != want {
		t.Errorf("Get().ID = %d; want %d", got, want)
	}
}

func TestController_Get_WithScheduler(t *testing.T) {
	t.Parallel()
	h := &mockHandler{
		status:    http.StatusOK,
		body:      `{"id":123, "name":"scheduled"}`,
		resHeader: http.Header{"Cache-Control": {"max-age=1"}},
	}

	s := httptest.NewServer(h)
	defer s.Close()

	sched := scheduler.New(t.Context())
	defer sched.Shutdown()

	c := cache.NewController(s.URL, mockMapper)
	sched.Dispatch(c)

	select {
	case <-c.Ready():
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for cache to become ready")
	}

	res, ok := c.Get()
	if !ok {
		t.Errorf("Get() ok = %t; want %t", ok, true)
	}
	if got, want := res, (mockResource{ID: 123, Name: "scheduled"}); got != want {
		t.Errorf("Get() resource = %v; want %v", got, want)
	}
	if got := h.Count(); got < 1 {
		t.Errorf("Count() = %d; want >= 1", got)
	}
}

func TestController_Run_ContextCancellation(t *testing.T) {
	t.Parallel()
	h := &mockHandler{
		sleep:  100 * time.Millisecond,
		status: http.StatusOK,
	}

	s := httptest.NewServer(h)
	defer s.Close()
	c := cache.NewController(s.URL, mockMapper)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	c.Run(ctx)
	if got, want := h.Count(), 0; got != want {
		t.Errorf("Count() = %d; want %d", got, want)
	}
}

func TestNewController_Options(t *testing.T) {
	t.Run("with client overrides others", func(t *testing.T) {
		t.Parallel()
		var used atomic.Bool
		transport := &mockRoundTripper{
			roundTrip: func(r *http.Request) (*http.Response, error) {
				used.Store(true)
				if got := r.Header.Get("X-Test"); len(got) != 0 {
					t.Errorf("Header X-Test = %q; want empty", got)
				}
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			},
		}
		cli := &http.Client{Transport: transport}
		c := cache.NewController("http://a.b", mockMapper,
			cache.WithClient(cli),
			cache.WithHeader("X-Test", "value"),
			cache.WithTimeout(1*time.Nanosecond),
		)
		c.Run(t.Context())
		if !used.Load() {
			t.Error("custom client's transport was not used")
		}
	})

	t.Run("with header", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{status: http.StatusNoContent}
		s := httptest.NewServer(h)
		defer s.Close()

		const (
			xFoo = "X-Foo"
			xBaz = "X-Baz"
		)

		c := cache.NewController(
			s.URL,
			mockMapper,
			cache.WithHeader(xFoo, "bar"),
			cache.WithHeader(xBaz, "qux"),
		)

		c.Run(t.Context())

		if got, want := h.RequestHeader(xFoo), "bar"; got != want {
			t.Errorf("RequestHeader(%q) = %q; want %q", xFoo, got, want)
		}
		if got, want := h.RequestHeader(xBaz), "qux"; got != want {
			t.Errorf("RequestHeader(%q) = %q; want %q", xBaz, got, want)
		}
	})
}
