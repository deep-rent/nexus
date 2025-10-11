package cache_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resource struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

var mapper cache.Mapper[resource] = func(body []byte) (resource, error) {
	var r resource
	err := json.Unmarshal(body, &r)
	return r, err
}

var errorMapper cache.Mapper[resource] = func(body []byte) (resource, error) {
	return resource{}, errors.New("parsing failed")
}

type mockHandler struct {
	mu        sync.Mutex
	status    int
	header    http.Header
	reqHeader http.Header
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

	for k, v := range h.header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(h.status)
	if h.body != "" {
		io.WriteString(w, h.body)
	}
}

func (h *mockHandler) getReqCount() int {
	return int(h.count.Load())
}

func (h *mockHandler) getReqHeader(key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reqHeader.Get(key)
}

func TestController_GetAndReady(t *testing.T) {
	h := &mockHandler{
		status: http.StatusOK,
		body:   `{"id":1, "name":"test"}`,
	}
	s := httptest.NewServer(h)
	defer s.Close()
	c := cache.NewController(s.URL, mapper)
	_, ok := c.Get()
	assert.False(t, ok, "Get should return false before first fetch")
	select {
	case <-c.Ready():
		t.Fatal("Ready channel should block before first fetch")
	default:
	}
	d := c.Run(context.Background())
	assert.NotZero(t, d, "Run should return a non-zero delay")
	r, ok := c.Get()
	assert.True(t, ok, "Get should return true after successful fetch")
	assert.Equal(t, resource{ID: 1, Name: "test"}, r)
	select {
	case <-c.Ready():
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Ready channel should be closed after successful fetch")
	}
	<-c.Ready()
}

func TestController_Run(t *testing.T) {
	h := &mockHandler{}
	s := httptest.NewServer(h)
	defer s.Close()
	minInt := 1 * time.Minute
	maxInt := 1 * time.Hour
	goodRes := resource{ID: 42, Name: "success"}
	goodBody, _ := json.Marshal(goodRes)
	tcs := []struct {
		name           string
		handler        *mockHandler
		mapper         cache.Mapper[resource]
		wantDelay      time.Duration
		wantDelayDelta time.Duration
		wantResource   resource
		wantOK         bool
		wantLogs       string
	}{
		{
			name: "200 OK with max-age",
			handler: &mockHandler{
				status: http.StatusOK,
				body:   string(goodBody),
				header: http.Header{"Cache-Control": {"max-age=120"}},
			},
			mapper:       mapper,
			wantDelay:    2 * time.Minute,
			wantResource: goodRes,
			wantOK:       true,
		},
		{
			name: "Clamp to min interval",
			handler: &mockHandler{
				status: http.StatusOK,
				body:   string(goodBody),
				header: http.Header{"Cache-Control": {"max-age=30"}},
			},
			mapper:       mapper,
			wantDelay:    minInt,
			wantResource: goodRes,
			wantOK:       true,
		},
		{
			name: "Clamp to max interval",
			handler: &mockHandler{
				status: http.StatusOK,
				body:   string(goodBody),
				header: http.Header{"Cache-Control": {"max-age=7200"}},
			},
			mapper:       mapper,
			wantDelay:    maxInt,
			wantResource: goodRes,
			wantOK:       true,
		},
		{
			name: "no-store header",
			handler: &mockHandler{
				status: http.StatusOK,
				body:   string(goodBody),
				header: http.Header{"Cache-Control": {"no-store"}},
			},
			mapper:       mapper,
			wantDelay:    minInt,
			wantResource: goodRes,
			wantOK:       true,
		},
		{
			name: "500 Server Error",
			handler: &mockHandler{
				status: http.StatusInternalServerError,
				body:   "error",
			},
			mapper:       mapper,
			wantDelay:    minInt,
			wantResource: resource{},
			wantOK:       false,
			wantLogs:     "Received a non-retriable HTTP status code",
		},
		{
			name:         "Mapper Error",
			handler:      &mockHandler{status: http.StatusOK, body: `invalid`},
			mapper:       errorMapper,
			wantDelay:    minInt,
			wantResource: resource{},
			wantOK:       false,
			wantLogs:     "Couldn't parse response body",
		},
		{
			name:         "Body Read Error",
			handler:      &mockHandler{status: http.StatusOK, body: "ok"},
			mapper:       mapper,
			wantDelay:    minInt,
			wantResource: resource{},
			wantOK:       false,
			wantLogs:     "Failed to read response body",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			h.mu.Lock()
			h.status = tc.handler.status
			h.header = tc.handler.header
			h.body = tc.handler.body
			h.sleep = tc.handler.sleep
			h.count.Store(0)
			h.mu.Unlock()
			if tc.name == "Body Read Error" {
				s.Config.Handler = http.HandlerFunc(func(
					w http.ResponseWriter, _ *http.Request,
				) {
					w.Header().Set("Content-Length", "10")
					w.WriteHeader(http.StatusOK)
					io.WriteString(w, "short")
				})
			} else {
				s.Config.Handler = h
			}
			var logBuf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&logBuf, nil))
			c := cache.NewController(s.URL, tc.mapper,
				cache.WithMinInterval(minInt),
				cache.WithMaxInterval(maxInt),
				cache.WithLogger(log),
				cache.WithRetryOptions(retry.WithAttemptLimit(1)),
			)
			d := c.Run(context.Background())
			if tc.wantDelayDelta > 0 {
				assert.InDelta(
					t,
					tc.wantDelayDelta,
					d,
					float64(time.Second),
					"delay should be approximately correct",
				)
			} else {
				assert.Equal(t, tc.wantDelay, d)
			}
			res, ok := c.Get()
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantResource, res)
			if tc.wantLogs != "" {
				assert.Contains(t, logBuf.String(), tc.wantLogs)
			}
			if tc.wantOK {
				select {
				case <-c.Ready():
				default:
					t.Error("Ready() should be closed on success")
				}
			}
		})
	}
}

func TestController_Run_ConditionalHeaders(t *testing.T) {
	h := &mockHandler{}
	s := httptest.NewServer(h)
	defer s.Close()
	c := cache.NewController(s.URL, mapper)
	h.status = http.StatusOK
	h.body = `{"id":1}`
	h.header = http.Header{
		"Etag":          {`"v1"`},
		"Last-Modified": {"some-date"},
	}
	c.Run(context.Background())
	require.Equal(t, 1, h.getReqCount(), "Expected 1 request")
	assert.Empty(t, h.getReqHeader("If-None-Match"))
	assert.Empty(t, h.getReqHeader("If-Modified-Since"))
	h.status = http.StatusNotModified
	h.body = ""
	c.Run(context.Background())
	require.Equal(t, 2, h.getReqCount(), "Expected 2 requests")
	assert.Equal(t, `"v1"`, h.getReqHeader("If-None-Match"))
	assert.Equal(t, "some-date", h.getReqHeader("If-Modified-Since"))
	res, ok := c.Get()
	require.True(t, ok)
	assert.Equal(t, 1, res.ID)
}

func TestController_WithScheduler(t *testing.T) {
	h := &mockHandler{
		status: http.StatusOK,
		body:   `{"id":123, "name":"scheduled"}`,
		header: http.Header{"Cache-Control": {"max-age=1"}},
	}
	s := httptest.NewServer(h)
	defer s.Close()
	sched := scheduler.New(context.Background())
	c := cache.NewController(s.URL, mapper)
	sched.Dispatch(c)
	select {
	case <-c.Ready():
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for cache to become ready")
	}
	sched.Shutdown()
	res, ok := c.Get()
	assert.True(t, ok)
	assert.Equal(t, resource{ID: 123, Name: "scheduled"}, res)
	assert.GreaterOrEqual(t, h.getReqCount(), 1, "handler should have been called at least once")
}

func TestController_Run_ContextCancellation(t *testing.T) {
	h := &mockHandler{
		sleep:  100 * time.Millisecond,
		status: http.StatusOK,
	}
	s := httptest.NewServer(h)
	defer s.Close()
	c := cache.NewController(s.URL, mapper)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c.Run(ctx)
	assert.Zero(t, h.getReqCount(), "No request should complete if context is cancelled")
}

func TestNewController_Options(t *testing.T) {
	t.Run("WithClient overrides others", func(t *testing.T) {
		var transportUsed bool
		mockTransport := &mockRoundTripper{roundTripFunc: func(r *http.Request) (*http.Response, error) {
			transportUsed = true
			assert.Empty(t, r.Header.Get("X-Test"), "Header should not be set on custom client")
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
		}}
		cli := &http.Client{Transport: mockTransport}
		c := cache.NewController("http://a.b", mapper,
			cache.WithClient(cli),
			cache.WithHeader("X-Test", "value"),
			cache.WithTimeout(1*time.Nanosecond),
		)
		c.Run(context.Background())
		assert.True(t, transportUsed, "Custom client's transport was not used")
	})
	t.Run("WithHeader", func(t *testing.T) {
		h := &mockHandler{status: http.StatusNoContent}
		s := httptest.NewServer(h)
		defer s.Close()
		c := cache.NewController(s.URL, mapper,
			cache.WithHeader("X-Foo", "bar"),
			cache.WithHeader("X-Baz", "qux"),
		)
		c.Run(context.Background())
		assert.Equal(t, "bar", h.getReqHeader("X-Foo"))
		assert.Equal(t, "qux", h.getReqHeader("X-Baz"))
	})
}

type mockRoundTripper struct {
	roundTripFunc func(*http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.roundTripFunc(r)
}
