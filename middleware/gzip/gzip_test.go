package gzip_test

import (
	compress "compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/middleware/gzip"
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
		opts      []gzip.Option
		wantEnc   string
		wantZip   bool
	}

	const payload = "This is a test payload that is long enough to be compressed."

	tests := []test{
		{
			name:      "compresses text/plain",
			acceptEnc: "gzip",
			mediaType: "text/plain",
			preEnc:    "",
			body:      payload,
			opts:      nil,
			wantEnc:   "gzip",
			wantZip:   true,
		},
		{
			name:      "no compress on missing accept-encoding",
			acceptEnc: "",
			mediaType: "text/plain",
			preEnc:    "",
			body:      payload,
			opts:      nil,
			wantEnc:   "",
			wantZip:   false,
		},
		{
			name:      "no compress on other accept-encoding",
			acceptEnc: "deflate, br",
			mediaType: "text/plain",
			preEnc:    "",
			body:      payload,
			opts:      nil,
			wantEnc:   "",
			wantZip:   false,
		},
		{
			name:      "no compress on existing content-encoding",
			acceptEnc: "gzip",
			mediaType: "text/plain",
			preEnc:    "br",
			body:      payload,
			opts:      nil,
			wantEnc:   "br",
			wantZip:   false,
		},
		{
			name:      "no compress on excluded exact match",
			acceptEnc: "gzip",
			mediaType: "application/pdf",
			preEnc:    "",
			body:      payload,
			opts:      nil,
			wantEnc:   "",
			wantZip:   false,
		},
		{
			name:      "no compress on excluded prefix match",
			acceptEnc: "gzip",
			mediaType: "image/png",
			preEnc:    "",
			body:      payload,
			opts:      nil,
			wantEnc:   "",
			wantZip:   false,
		},
		{
			name:      "compresses prefix of excluded type",
			acceptEnc: "gzip",
			mediaType: "application/pd",
			preEnc:    "",
			body:      payload,
			opts:      nil,
			wantEnc:   "gzip",
			wantZip:   true,
		},
		{
			name:      "no compress on custom excluded exact",
			acceptEnc: "gzip",
			mediaType: "application/json",
			preEnc:    "",
			body:      payload,
			opts:      []gzip.Option{gzip.WithExcludeMimeTypes("application/json")},
			wantEnc:   "",
			wantZip:   false,
		},
		{
			name:      "no compress on custom excluded prefix",
			acceptEnc: "gzip",
			mediaType: "text/vtt",
			preEnc:    "",
			body:      payload,
			opts:      []gzip.Option{gzip.WithExcludeMimeTypes("text/*")},
			wantEnc:   "",
			wantZip:   false,
		},
		{
			name:      "handles empty body",
			acceptEnc: "gzip",
			mediaType: "text/plain",
			preEnc:    "",
			body:      "",
			opts:      nil,
			wantEnc:   "gzip",
			wantZip:   true,
		},
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

			chain := gzip.New(tc.opts...)(h)

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
				gzr, err := compress.NewReader(w.Body)
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
	pipe := gzip.New()
	h := pipe(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	gzr, err := compress.NewReader(w.Body)
	require.NoError(t, err)
	data, err := io.ReadAll(gzr)
	require.NoError(t, err)
	err = gzr.Close()
	require.NoError(t, err)

	assert.Equal(t, "foobar", string(data))
}
