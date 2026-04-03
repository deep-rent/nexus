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

package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/proxy"
)

func TestHandler_ServeHTTP_EndToEnd(t *testing.T) {
	t.Parallel()

	msg := "hello"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(msg))
	})

	server1 := httptest.NewServer(handler)
	defer server1.Close()

	u, err := url.Parse(server1.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) err = %v", server1.URL, err)
	}

	server2 := httptest.NewServer(proxy.NewHandler(u))
	defer server2.Close()

	res, err := http.Get(server2.URL)
	if err != nil {
		t.Fatalf("http.Get(%q) err = %v", server2.URL, err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Errorf("res.StatusCode = %d; want %d", got, want)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(res.Body) err = %v", err)
	}
	if got, want := string(b), msg; got != want {
		t.Errorf("res.Body = %q; want %q", got, want)
	}
}

func TestHandler_ServeHTTP_Rewrite(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "Secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	u, _ := url.Parse(server.URL)

	rewrite := func(next proxy.RewriteFunc) proxy.RewriteFunc {
		return func(pr *httputil.ProxyRequest) {
			next(pr)
			pr.Out.Header.Set("X-Auth", "Secret")
		}
	}

	h := proxy.NewHandler(u, proxy.WithRewrite(rewrite))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	h.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}
}

func TestErrorHandler_Handle_StatusAndLogging(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		code int
		log  string
	}{
		{
			"refused",
			errors.New("dial tcp"),
			http.StatusBadGateway,
			"Upstream request failed",
		},
		{
			"timeout 1",
			context.DeadlineExceeded,
			http.StatusGatewayTimeout,
			"Upstream request timed out",
		},
		{
			"timeout 2",
			http.ErrHandlerTimeout,
			http.StatusGatewayTimeout,
			"Upstream request timed out",
		},
		{
			"canceled",
			context.Canceled,
			0,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			h := proxy.NewErrorHandler(logger)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil).WithContext(t.Context())

			h(rec, req, tt.err)

			if tt.code != 0 {
				if got, want := rec.Code, tt.code; got != want {
					t.Errorf("rec.Code = %d; want %d", got, want)
				}
			}
			if tt.log != "" {
				if got := buf.String(); !strings.Contains(got, tt.log) {
					t.Errorf("log output = %q; want it to contain %q", got, tt.log)
				}
			} else {
				if got := buf.Len(); got != 0 {
					t.Errorf("buf.Len() = %d; want 0", got)
				}
			}
		})
	}
}

func TestNewHandler_Options_Configuration(t *testing.T) {
	t.Parallel()

	u, _ := url.Parse("http://example.com")
	transport := &http.Transport{}
	d := 1 * time.Second

	t.Run("valid options", func(t *testing.T) {
		t.Parallel()

		h := proxy.NewHandler(u,
			proxy.WithTransport(transport),
			proxy.WithFlushInterval(d),
			proxy.WithMinBufferSize(1024),
			proxy.WithMaxBufferSize(2048),
		)

		rp, ok := h.(*httputil.ReverseProxy)
		if !ok {
			t.Fatalf("h is %T; want *httputil.ReverseProxy", h)
		}

		if got, want := rp.Transport, transport; got != want {
			t.Errorf("rp.Transport = %p; want %p", got, want)
		}
		if got, want := rp.FlushInterval, d; got != want {
			t.Errorf("rp.FlushInterval = %v; want %v", got, want)
		}
		if rp.BufferPool == nil {
			t.Error("rp.BufferPool is nil; want non-nil")
		}
	})

	t.Run("ignored invalid options", func(t *testing.T) {
		t.Parallel()

		h := proxy.NewHandler(u,
			proxy.WithMinBufferSize(-1),
			proxy.WithMaxBufferSize(0),
			proxy.WithErrorHandler(nil),
			proxy.WithRewrite(nil),
			proxy.WithLogger(nil),
			proxy.WithTransport(nil),
		)

		rp, ok := h.(*httputil.ReverseProxy)
		if !ok {
			t.Fatalf("h is %T; want *httputil.ReverseProxy", h)
		}

		if rp.BufferPool == nil {
			t.Error("rp.BufferPool is nil; want non-nil")
		}
		if rp.ErrorHandler == nil {
			t.Error("rp.ErrorHandler is nil; want non-nil")
		}
		if rp.Rewrite == nil {
			t.Error("rp.Rewrite is nil; want non-nil")
		}
		// if rp.Director != nil { //nolint:staticcheck
		// 	t.Error("rp.Director is non-nil; want nil")
		// }
	})
}

func TestWithErrorHandler_Functional_CustomHandler(t *testing.T) {
	t.Parallel()

	u, _ := url.Parse("http://example.com")
	called := false

	wantErr := errors.New("sentinel")

	ehf := func(log *slog.Logger) proxy.ErrorHandler {
		return func(w http.ResponseWriter, r *http.Request, err error) {
			called = true
			if !errors.Is(err, wantErr) {
				t.Errorf("ErrorHandler(err) = %v; want %v", err, wantErr)
			}
			w.WriteHeader(http.StatusTeapot)
		}
	}

	h := proxy.NewHandler(u, proxy.WithErrorHandler(ehf))
	rp, ok := h.(*httputil.ReverseProxy)
	if !ok {
		t.Fatalf("h is %T; want *httputil.ReverseProxy", h)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil).WithContext(t.Context())

	rp.ErrorHandler(rec, req, wantErr)

	if !called {
		t.Error("ErrorHandler was not called")
	}
	if got, want := rec.Code, http.StatusTeapot; got != want {
		t.Errorf("rec.Code = %d; want %d", got, want)
	}
}
