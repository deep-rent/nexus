package middleware_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mw "github.com/deep-rent/nexus/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChain(t *testing.T) {
	t.Run("Chains pipes in correct order", func(t *testing.T) {
		var order []string
		rec := func(id string) mw.Pipe {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					order = append(order, id)
					next.ServeHTTP(w, r)
				})
			}
		}

		h := mw.Chain(okHandler, rec("a"), rec("b"), rec("c"))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

		exp := "a,b,c"
		act := strings.Join(order, ",")
		assert.Equal(t, exp, act)
	})

	t.Run("Ignores nil pipes", func(t *testing.T) {
		var called bool
		p := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				next.ServeHTTP(w, r)
			})
		}

		h := mw.Chain(okHandler, nil, p, nil)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		assert.True(t, called)
	})

	t.Run("Returns original handler if no pipes", func(t *testing.T) {
		h := mw.Chain(okHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "ok", rr.Body.String())
	})
}

func TestRecover(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf)
	pipe := mw.Recover(logger)

	t.Run("Recovers from panic", func(t *testing.T) {
		buf.Reset()
		h := pipe(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("test")
		}))
		req := httptest.NewRequest("GET", "/panic", nil)
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		out := buf.String()
		assert.Contains(t, out, "Panic caught by middleware")
		assert.Contains(t, out, `error=test`)
		assert.Contains(t, out, `url=/panic`)
		assert.Contains(t, out, `stack=`)
	})

	t.Run("Does nothing if no panic", func(t *testing.T) {
		buf.Reset()
		h := pipe(okHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/ok", nil))

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "ok", rr.Body.String())
		assert.Empty(t, buf.String())
	})
}

func TestRequestID(t *testing.T) {
	var captured string
	trap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = mw.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := mw.RequestID()(trap)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	id := rr.Header().Get("X-Request-ID")
	require.NotEmpty(t, id)
	assert.Len(t, id, 32)
	require.NotEmpty(t, captured)
	assert.Equal(t, id, captured)
}

func TestGetSetRequestID(t *testing.T) {
	t.Run("Get from empty context", func(t *testing.T) {
		id := mw.GetRequestID(context.Background())
		assert.Empty(t, id)
	})

	t.Run("Set and get ID", func(t *testing.T) {
		exp := "test-id"
		ctx := mw.SetRequestID(context.Background(), exp)
		act := mw.GetRequestID(ctx)
		assert.Equal(t, exp, act)
	})
}

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf)
	pipe := mw.Log(logger)

	t.Run("Logs with non-default status", func(t *testing.T) {
		buf.Reset()
		final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		h := pipe(final)
		req := httptest.NewRequest("POST", "/path?q=1", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("User-Agent", "test-agent")
		req = req.WithContext(mw.SetRequestID(req.Context(), "test-id"))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		out := buf.String()
		assert.Contains(t, out, `level=DEBUG msg="HTTP request handled"`)
		assert.Contains(t, out, `id=test-id`)
		assert.Contains(t, out, `method=POST`)
		assert.Contains(t, out, `url="/path?q=1"`)
		assert.Contains(t, out, `remote=1.2.3.4:12345`)
		assert.Contains(t, out, `agent=test-agent`)
		assert.Contains(t, out, `status=404`)
		assert.Contains(t, out, `duration=`)
	})

	t.Run("Logs with default status", func(t *testing.T) {
		buf.Reset()
		final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("ok"))
		})

		ch := pipe(final)
		rr := httptest.NewRecorder()
		ch.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), `status=200`)
	})
}

func TestVolatile(t *testing.T) {
	h := mw.Volatile()(okHandler)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	cc := "no-store, no-cache, must-revalidate, proxy-revalidate"

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, cc, rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	assert.Equal(t, "0", rr.Header().Get("Expires"))
}

func TestSecure(t *testing.T) {
	t.Run("uses default config", func(t *testing.T) {
		h := mw.Secure(mw.DefaultSecurityConfig)(okHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		assert.Equal(t, http.StatusOK, rr.Code)

		hsts := rr.Header().Get("Strict-Transport-Security")
		assert.Contains(t, hsts, "max-age=31536000")
		assert.Contains(t, hsts, "includeSubDomains")

		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
	})

	t.Run("applies custom config", func(t *testing.T) {
		cfg := mw.SecurityConfig{
			STSMaxAge:            60,
			STSIncludeSubdomains: false,
			FrameOptions:         "SAMEORIGIN",
			NoSniff:              true,
			CSP:                  "default-src 'self'",
			ReferrerPolicy:       "no-referrer",
		}
		h := mw.Secure(cfg)(okHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		hdr := rr.Header()
		assert.Equal(t, "max-age=60", hdr.Get("Strict-Transport-Security"))
		assert.Equal(t, "SAMEORIGIN", hdr.Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", hdr.Get("X-Content-Type-Options"))
		assert.Equal(t, "default-src 'self'", hdr.Get("Content-Security-Policy"))
		assert.Equal(t, "no-referrer", hdr.Get("Referrer-Policy"))
	})

	t.Run("sets no headers on empty config", func(t *testing.T) {
		cfg := mw.SecurityConfig{}
		h := mw.Secure(cfg)(okHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		hdr := rr.Header()
		assert.Empty(t, hdr.Get("Strict-Transport-Security"))
		assert.Empty(t, hdr.Get("X-Frame-Options"))
		assert.Empty(t, hdr.Get("X-Content-Type-Options"))
		assert.Empty(t, hdr.Get("Content-Security-Policy"))
		assert.Empty(t, hdr.Get("Referrer-Policy"))
	})
}

func newLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
})
