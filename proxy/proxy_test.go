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
		w.Write([]byte(msg))
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
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)

	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, msg, string(b))
}

func TestDirector(t *testing.T) {
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

	f := func(next proxy.Director) proxy.Director {
		return func(req *http.Request) {
			next(req)
			req.Header.Set("X-Auth", "Secret")
		}
	}

	h := proxy.NewHandler(u, proxy.WithDirector(f))
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
			"Timeout",
			context.DeadlineExceeded,
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

	h := proxy.NewHandler(u,
		proxy.WithTransport(tr),
		proxy.WithFlushInterval(d),
	)

	rp, ok := h.(*httputil.ReverseProxy)
	require.True(t, ok)

	assert.Equal(t, tr, rp.Transport)
	assert.Equal(t, d, rp.FlushInterval)
	assert.NotNil(t, rp.BufferPool)
}
