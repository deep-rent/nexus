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

package gzip_test

import (
	compress "compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/middleware/gzip"
)

func TestMiddleware(t *testing.T) {
	t.Parallel()

	const payload = "This is a test payload that is long enough to be compressed."

	tests := []struct {
		name      string
		acceptEnc string
		mediaType string
		preEnc    string
		body      string
		opts      []gzip.Option
		wantEnc   string
		wantZip   bool
	}{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.mediaType)
				if tt.preEnc != "" {
					w.Header().Set("Content-Encoding", tt.preEnc)
				}
				_, _ = w.Write([]byte(tt.body))
			})

			chain := gzip.New(tt.opts...)(h)

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept-Encoding", tt.acceptEnc)

			w := httptest.NewRecorder()
			chain.ServeHTTP(w, r)

			if got, want := w.Code, http.StatusOK; got != want {
				t.Fatalf("Middleware() status = %d; want %d", got, want)
			}

			hdr := w.Header()

			if got, want := hdr.Get("Content-Encoding"), tt.wantEnc; got != want {
				t.Errorf("Middleware() Content-Encoding = %q; want %q", got, want)
			}

			if tt.wantEnc == "gzip" {
				if got, want := hdr.Get("Vary"), "Accept-Encoding"; got != want {
					t.Errorf("Middleware() Vary = %q; want %q", got, want)
				}
				if got := hdr.Get("Content-Length"); len(got) != 0 {
					t.Errorf("Middleware() Content-Length = %q; want empty", got)
				}
			}

			var body string
			if tt.wantZip {
				gzr, err := compress.NewReader(w.Body)
				if err != nil {
					t.Fatalf("compress.NewReader() error = %v", err)
				}
				data, err := io.ReadAll(gzr)
				if err != nil {
					t.Fatalf("io.ReadAll(gzip) error = %v", err)
				}
				if err := gzr.Close(); err != nil {
					t.Errorf("gzr.Close() error = %v", err)
				}
				body = string(data)
			} else {
				data, err := io.ReadAll(w.Body)
				if err != nil {
					t.Fatalf("io.ReadAll() error = %v", err)
				}
				body = string(data)
			}

			if got, want := body, tt.body; got != want {
				t.Errorf("Middleware() body = %q; want %q", got, want)
			}
		})
	}
}

func TestFlusher(t *testing.T) {
	t.Parallel()

	pipe := gzip.New()
	h := pipe(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatalf("ResponseWriter does not implement http.Flusher")
		}

		if _, err := w.Write([]byte("foo")); err != nil {
			t.Errorf("w.Write(foo) error = %v", err)
		}
		flusher.Flush()

		if _, err := w.Write([]byte("bar")); err != nil {
			t.Errorf("w.Write(bar) error = %v", err)
		}
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if got, want := w.Code, http.StatusOK; got != want {
		t.Fatalf("Flusher status = %d; want %d", got, want)
	}

	if got, want := w.Header().Get("Content-Encoding"), "gzip"; got != want {
		t.Errorf("Flusher Content-Encoding = %q; want %q", got, want)
	}

	if !w.Flushed {
		t.Errorf("Flusher was not called")
	}

	gzr, err := compress.NewReader(w.Body)
	if err != nil {
		t.Fatalf("compress.NewReader() error = %v", err)
	}
	data, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	if err := gzr.Close(); err != nil {
		t.Errorf("gzr.Close() error = %v", err)
	}

	if got, want := string(data), "foobar"; got != want {
		t.Errorf("Flusher body = %q; want %q", got, want)
	}
}
