package middleware_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mw "github.com/deep-rent/nexus/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
})

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

		h := mw.Chain(okHandler, rec("A"), rec("B"), rec("C"))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

		exp := "A,B,C"
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
		assert.Equal(t, "OK", rr.Body.String())
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
		assert.Equal(t, "OK", rr.Body.String())
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
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "Not Found")
		})

		ch := pipe(h)
		req := httptest.NewRequest("POST", "/path?q=1", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("User-Agent", "test-agent")
		req = req.WithContext(mw.SetRequestID(req.Context(), "test-id"))

		rr := httptest.NewRecorder()
		ch.ServeHTTP(rr, req)

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
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		})

		ch := pipe(h)
		rr := httptest.NewRecorder()
		ch.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), `status=200`)
	})
}

func TestIntegration(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf)

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, mw.GetRequestID(r.Context()))
		w.WriteHeader(http.StatusAccepted)
	})

	h := mw.Chain(
		final, mw.Recover(logger),
		mw.RequestID(),
		mw.Log(logger),
	)

	req := httptest.NewRequest("GET", "/int", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	id := rr.Header().Get("X-Request-ID")
	require.NotEmpty(t, id)
	assert.Equal(t, http.StatusAccepted, rr.Code)

	out := buf.String()
	assert.Contains(t, out, "level=DEBUG")
	assert.Contains(t, out, "id="+id)
	assert.Contains(t, out, "status=202")
}
