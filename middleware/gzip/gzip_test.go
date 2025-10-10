package gzip_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	mw "github.com/deep-rent/nexus/middleware/gzip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	type test struct {
		name      string
		acceptEnc string
		mediaType string
		preEnc    string
		body      string
		opts      []mw.Option
		wantEnc   string
		wantZip   bool
	}

	const pld = "This is a test payload that is long enough to be compressed."
	opts1 := []mw.Option{mw.WithExcludeMimeTypes("application/vnd.custom")}
	opts2 := []mw.Option{mw.WithExcludeMimeTypes("text/*")}

	tests := []test{
		{"compresses text/plain", "gzip", "text/plain", "", pld, nil, "gzip", true},
		{"no compress on missing accept-encoding", "", "text/plain", "", pld, nil, "", false},
		{"no compress on other accept-encoding", "deflate, br", "text/plain", "", pld, nil, "", false},
		{"no compress on existing content-encoding", "gzip", "text/plain", "br", pld, nil, "br", false},
		{"no compress on excluded exact match", "gzip", "application/pdf", "", pld, nil, "", false},
		{"no compress on excluded prefix match", "gzip", "image/png", "", pld, nil, "", false},
		{"compresses prefix of excluded type", "gzip", "application/pd", "", pld, nil, "gzip", true},
		{"no compress on custom excluded exact", "gzip", "application/vnd.custom", "", pld, opts1, "", false},
		{"no compress on custom excluded prefix", "gzip", "text/vtt", "", pld, opts2, "", false},
		{"handles empty body", "gzip", "text/plain", "", "", nil, "gzip", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.mediaType)
				if tc.preEnc != "" {
					w.Header().Set("Content-Encoding", tc.preEnc)
				}
				w.Write([]byte(tc.body))
			})

			chain := mw.New(tc.opts...)(h)

			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept-Encoding", tc.acceptEnc)

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
			assert.Equal(t, tc.body, body)
		})
	}
}

func TestFlusher(t *testing.T) {
	h := mw.New()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		_, err := w.Write([]byte("foo"))
		require.NoError(t, err)
		flusher.Flush()

		_, err = w.Write([]byte("bar"))
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

	assert.Equal(t, "foobar", string(data))
}
