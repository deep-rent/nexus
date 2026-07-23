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

package gzip

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/deep-rent/nexus/net/header"
	"github.com/deep-rent/nexus/net/middleware"
)

// interceptor wraps an [http.ResponseWriter] to compress the response body.
//
// It transparently compresses the response body with gzip. It also implements
// [http.Hijacker] and [http.Flusher] to support protocol upgrades and
// streaming.
type interceptor struct {
	// ResponseWriter is the underlying writer being wrapped.
	http.ResponseWriter
	// gz is the active gzip writer for the current response.
	gz *gzip.Writer
	// exclude is the list of MIME types to skip.
	exclude []string
	// pool is the sync.Pool used for gzip writer reuse.
	pool *sync.Pool
	// wrote tracks if WriteHeader has been called.
	wrote bool
	// hijacked tracks if the connection has been hijacked.
	hijacked bool
	// skip determines whether to skip compression for this response.
	skip bool
}

// WriteHeader sets the Content-Encoding header and deletes Content-Length.
//
// Deleting Content-Length is crucial, as the size of the compressed content is
// unknown until it is fully written.
func (w *interceptor) WriteHeader(statusCode int) {
	// Forward informational (1xx) responses without latching any state; the
	// final status line and the compression decision are still to come.
	if statusCode < 200 {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}

	if w.wrote {
		return
	}
	w.wrote = true

	// Responses that must not carry a body would otherwise receive the gzip
	// header and footer bytes, which the server rejects.
	if statusCode == http.StatusNoContent ||
		statusCode == http.StatusResetContent ||
		statusCode == http.StatusNotModified {
		w.skip = true
	}

	if w.ResponseWriter.Header().Get("Content-Encoding") != "" {
		w.skip = true
	}

	mime := header.MediaType(w.Header())
	if mime != "" {
		for _, t := range w.exclude {
			if strings.HasSuffix(t, "*") {
				if strings.HasPrefix(mime, t[:len(t)-1]) {
					w.skip = true
					break
				}
			} else {
				if mime == t {
					w.skip = true
					break
				}
			}
		}
	}

	if !w.skip {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		w.gz = w.pool.Get().(*gzip.Writer)
		w.gz.Reset(w.ResponseWriter)
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

// Write compresses the data and writes it to the underlying
// [http.ResponseWriter].
//
// It also handles setting the Content-Encoding header on the first write.
func (w *interceptor) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.skip {
		return w.ResponseWriter.Write(b)
	}
	return w.gz.Write(b)
}

// Close flushes buffered data, closes the gzip writer, and returns it to the
// pool.
func (w *interceptor) Close() {
	// If the connection was hijacked, don't write the gzip footer.
	// Just return the writer to the pool.
	if w.gz != nil {
		if !w.hijacked {
			_ = w.gz.Close()
		}
		w.gz.Reset(io.Discard)
		w.pool.Put(w.gz)
		w.gz = nil
	}
}

// Hijack implements the [http.Hijacker] interface.
//
// It allows the underlying connection to be taken over for protocol upgrades
// like WebSockets.
func (w *interceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	w.hijacked = true
	return hijacker.Hijack()
}

// Flush implements the [http.Flusher] interface.
//
// It enables incremental flushing of the response body, which is useful for
// streaming data.
func (w *interceptor) Flush() {
	// Flushing transmits the response headers, so the compression decision
	// must be made first; otherwise a later Write would start a gzip stream
	// whose Content-Encoding header can no longer be announced.
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.gz != nil {
			_ = w.gz.Flush()
		}
		flusher.Flush()
	}
}

// Ensure interceptor implements the necessary contracts.
var (
	_ http.ResponseWriter = (*interceptor)(nil)
	_ http.Hijacker       = (*interceptor)(nil)
	_ http.Flusher        = (*interceptor)(nil)
)

// New creates a middleware [middleware.Pipe] that compresses HTTP responses.
//
// The middleware is a no-op if the client does not send an Accept-Encoding
// header including "gzip" or if the response already has a non-empty
// Content-Encoding header. It adds the "Vary: Accept-Encoding" header to
// responses to prevent cache poisoning.
func New(opts ...Option) middleware.Pipe {
	cfg := config{
		level:   DefaultCompression,
		exclude: defaultExcludeList,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	pool := &sync.Pool{
		New: func() any {
			// Errors are ignored as they only occur with an invalid level,
			// which we guard against in the option.
			gw, _ := gzip.NewWriterLevel(io.Discard, cfg.level)
			return gw
		},
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip HEAD requests (no body to compress) and clients that do
			// not accept gzip compression.
			if r.Method == http.MethodHead ||
				!header.Accepts(r.Header.Get("Accept-Encoding"), "gzip") ||
				w.Header().Get("Content-Encoding") != "" {
				next.ServeHTTP(w, r)
				return
			}

			// Create the gzip response writer.
			gzw := &interceptor{
				ResponseWriter: w,
				exclude:        cfg.exclude,
				pool:           pool,
			}
			defer gzw.Close()

			// Indicate that the response is subject to content negotiation.
			gzw.Header().Add("Vary", "Accept-Encoding")
			next.ServeHTTP(gzw, r)
		})
	}
}
