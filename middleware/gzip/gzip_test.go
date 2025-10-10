package gzip_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	middleware "github.com/deep-rent/nexus/middleware/gzip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGzipMiddleware(t *testing.T) {
	const payload = "This is a test payload that is long enough to be compressed."
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		if enc := r.Header.Get("X-Pre-Enc"); enc != "" {
			w.Header().Set("Content-Encoding", enc)
		}
		w.Write([]byte(payload))
	})

	tests := []struct {
		name      string
		acceptEnc string
		mediaType string
		preEnc    string
		opts      []middleware.Option
		wantEnc   string
		wantZip   bool
	}{
		{
			"compresses text/plain",
			"gzip", "text/plain", "", nil, "gzip", true,
		},
		{
			"no compress on missing accept-encoding",
			"", "text/plain", "", nil, "", false,
		},
		{
			"no compress on other accept-encoding",
			"deflate, br", "text/plain", "", nil, "", false,
		},
		{
			"no compress on existing content-encoding",
			"gzip", "text/plain", "br", nil, "br", false,
		},
		{
			"no compress on excluded exact match",
			"gzip", "application/pdf", "", nil, "", false,
		},
		{
			"no compress on excluded prefix match",
			"gzip", "image/png", "", nil, "", false,
		},
		{
			"compresses prefix of excluded type",
			"gzip", "application/pd", "", nil, "gzip", true,
		},
		{
			"no compress on custom excluded exact",
			"gzip", "application/vnd.custom", "", []middleware.Option{
				middleware.WithExcludeMimeTypes("application/vnd.custom"),
			}, "", false},
		{
			"no compress on custom excluded prefix",
			"gzip", "text/vtt", "", []middleware.Option{
				middleware.WithExcludeMimeTypes("text/*"),
			}, "", false},
		{
			"handles empty body",
			"gzip", "text/plain", "", nil, "gzip", true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mid := middleware.New(tc.opts...)
			chain := mid(h)

			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept-Encoding", tc.acceptEnc)
			r.Header.Set("Content-Type", tc.mediaType)
			if tc.preEnc != "" {
				r.Header.Set("X-Pre-Enc", tc.preEnc)
			}

			w := httptest.NewRecorder()
			chain.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.wantEnc, w.Header().Get("Content-Encoding"))

			if tc.wantEnc == "gzip" {
				assert.Equal(t, "Accept-Encoding", w.Header().Get("Vary"))
				assert.Empty(t, w.Header().Get("Content-Length"))
			}

			var body string
			if tc.wantZip {
				gzr, err := gzip.NewReader(w.Body)
				require.NoError(t, err)
				data, err := io.ReadAll(gzr)
				require.NoError(t, err)
				err = gzr.Close()
				require.NoError(t, err)
				body = string(data)
			} else {
				data, err := io.ReadAll(w.Body)
				require.NoError(t, err)
				body = string(data)
			}

			if tc.name == "handles empty body" {
				assert.Empty(t, body)
			} else {
				assert.Equal(t, payload, body)
			}
		})
	}
}

func TestGzip_Flusher(t *testing.T) {
	mid := middleware.New()
	h := mid(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		_, err := w.Write([]byte("first"))
		require.NoError(t, err)
		flusher.Flush()

		_, err = w.Write([]byte("second"))
		require.NoError(t, err)
	}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
	assert.True(t, w.Flushed)

	gzr, err := gzip.NewReader(w.Body)
	require.NoError(t, err)
	data, err := io.ReadAll(gzr)
	require.NoError(t, err)
	err = gzr.Close()
	require.NoError(t, err)

	assert.Equal(t, "firstsecond", string(data))
}
