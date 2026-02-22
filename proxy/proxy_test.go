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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/proxy"
)

func TestEndToEnd(t *testing.T) {
	msg := "hello"
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(msg))
	})
	ts := httptest.NewServer(hf)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	require.NoError(t, err)

	h := proxy.NewHandler(u)
	ps := httptest.NewServer(h)
	defer ps.Close()

	res, err := http.Get(ps.URL)
	require.NoError(t, err)
	defer func() {
		_ = res.Body.Close()
	}()

	assert.Equal(t, http.StatusOK, res.StatusCode)

	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, msg, string(b))
}

func TestRewrite(t *testing.T) {
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth") != "Secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(hf)
	defer ts.Close()

	u, _ := url.Parse(ts.URL)

	f := func(next proxy.RewriteFunc) proxy.RewriteFunc {
		return func(pr *httputil.ProxyRequest) {
			// Call the original/default rewrite to set up the target URL
			next(pr)
			// Modify the outbound request headers
			pr.Out.Header.Set("X-Auth", "Secret")
		}
	}

	h := proxy.NewHandler(u, proxy.WithRewrite(f))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestErrorHandler(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	h := proxy.NewErrorHandler(l)

	tests := []struct {
		n    string
		err  error
		code int
		log  string
	}{
		{
			"Refused",
			errors.New("dial tcp"),
			http.StatusBadGateway,
			"Upstream request failed",
		},
		{
			"Timeout 1",
			context.DeadlineExceeded,
			http.StatusGatewayTimeout,
			"Upstream request timed out",
		},
		{
			"Timeout 2",
			http.ErrHandlerTimeout,
			http.StatusGatewayTimeout,
			"Upstream request timed out",
		},
		{
			"Canceled",
			context.Canceled,
			0,
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.n, func(t *testing.T) {
			buf.Reset()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)

			h(rec, req, tc.err)

			if tc.code != 0 {
				assert.Equal(t, tc.code, rec.Code)
			}
			if tc.log != "" {
				assert.Contains(t, buf.String(), tc.log)
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestOptions(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	tr := &http.Transport{}
	d := time.Second

	t.Run("Valid Options", func(t *testing.T) {
		h := proxy.NewHandler(u,
			proxy.WithTransport(tr),
			proxy.WithFlushInterval(d),
			proxy.WithMinBufferSize(1024),
			proxy.WithMaxBufferSize(2048),
		)

		rp, ok := h.(*httputil.ReverseProxy)
		require.True(t, ok)

		assert.Equal(t, tr, rp.Transport)
		assert.Equal(t, d, rp.FlushInterval)
		assert.NotNil(t, rp.BufferPool)
	})

	t.Run("Ignored Invalid Options", func(t *testing.T) {
		h := proxy.NewHandler(u,
			proxy.WithMinBufferSize(-1),
			proxy.WithMaxBufferSize(0),
			proxy.WithErrorHandler(nil),
			proxy.WithRewrite(nil),
			proxy.WithLogger(nil),
			proxy.WithTransport(nil),
		)

		rp, ok := h.(*httputil.ReverseProxy)
		require.True(t, ok)

		assert.NotNil(t, rp.BufferPool)
		assert.NotNil(t, rp.ErrorHandler)
		assert.NotNil(t, rp.Rewrite)
		assert.Nil(t, rp.Director) // nolint:staticcheck
	})
}

func TestWithErrorHandler(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	called := false

	factory := func(log *slog.Logger) proxy.ErrorHandler {
		return func(w http.ResponseWriter, r *http.Request, err error) {
			called = true
			assert.Equal(t, assert.AnError, err)
			w.WriteHeader(http.StatusTeapot)
		}
	}

	h := proxy.NewHandler(u, proxy.WithErrorHandler(factory))
	rp, ok := h.(*httputil.ReverseProxy)
	require.True(t, ok)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	rp.ErrorHandler(rec, req, assert.AnError)

	assert.True(t, called)
	assert.Equal(t, http.StatusTeapot, rec.Code)
}
