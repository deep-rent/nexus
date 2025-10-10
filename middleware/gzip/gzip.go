// Package gzip provides an HTTP middleware for compressing response bodies
// using the gzip algorithm. It automatically adds the "Content-Encoding: gzip"
// header and compresses the payload for clients that support it (indicated by
// the "Accept-Encoding" request header).
//
// # Usage
//
// The middleware is designed to be efficient. It pools gzip writers to reduce
// memory allocations and gracefully skips compression for responses tha
// already have a "Content-Encoding" header set.
//
// Example:
//
//	// Create the final handler.
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Header().Set("Content-Type", "text/plain")
//		w.Write([]byte("This is a long string that will be compressed."))
//	})
//
//	// Create a gzip middleware pipe with the highest level if compression.
//	pipe := gzip.New(
//		gzip.WithCompressionLevel(gzip.BestCompression),
//		gzip.WithExcludeMimeTypes("text/*", "application/font-woff"),
//	)
//
//	// Apply the CORS middleware as one of the first layers.
//	chainedHandler := middleware.Chain(handler, pipe)
//
//	http.ListenAndServe(":8080", chainedHandler)
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

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/middleware"
)

// Mirror constants from the compress/gzip package for easy access without
// requiring an extra import.
const (
	BestCompression    = gzip.BestCompression
	BestSpeed          = gzip.BestSpeed
	DefaultCompression = gzip.DefaultCompression
	NoCompression      = gzip.NoCompression
)

// defaultExcludeList lists common media types that are already compressed.
var defaultExcludeList = []string{
	// Media
	"image/*",
	"video/*",
	"audio/*",
	// Fonts
	"font/*",
	// Archives & Documents
	"application/zip",
	"application/gzip",
	"application/pdf",
	"application/wasm",
}

// interceptor wraps an http.ResponseWriter to transparently compress the
// response body with gzip. It also implements http.Hijacker and http.Flusher to
// support protocol upgrades and streaming.
type interceptor struct {
	http.ResponseWriter
	gz       *gzip.Writer
	level    int
	exclude  []string
	pool     *sync.Pool
	header   bool // Tracks if WriteHeader has been called.
	hijacked bool // Tracks if the connection has been hijacked.
	skip     bool // Decide whether to skip compression.
}

// WriteHeader sets the Content-Encoding header and deletes Content-Length
// before writing the status code. Deleting Content-Length is crucial, as the
// size of the compressed content is unknown until it's fully written.
func (w *interceptor) WriteHeader(statusCode int) {
	if w.header {
		return
	}
	w.header = true

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

// Write compresses the data and writes it to the underlying ResponseWriter.
// It also handles setting the Content-Encoding header on the first write.
func (w *interceptor) Write(b []byte) (int, error) {
	if !w.header {
		w.WriteHeader(http.StatusOK)
	}
	if w.skip {
		return w.ResponseWriter.Write(b)
	}
	return w.gz.Write(b)
}

// Close flushes any buffered data, closes the gzip writer, and returns it to
// the pool.
func (w *interceptor) Close() {
	// If the connection was hijacked, don't write the gzip footer.
	// Just return the writer to the pool.
	if w.gz != nil {
		if !w.hijacked {
			w.gz.Close()
		}
		w.gz.Reset(io.Discard)
		w.pool.Put(w.gz)
		w.gz = nil
	}
}

// Hijack implements the http.Hijacker interface, allowing the underlying
// connection to be taken over for protocol upgrades like WebSockets.
func (w *interceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacking not supported")
	}
	w.hijacked = true
	return hijacker.Hijack()
}

// Flush implements the http.Flusher interface, enabling incremental flushing of
// the response body, which is useful for streaming data.
func (w *interceptor) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.gz != nil {
			w.gz.Flush()
		}
		flusher.Flush()
	}
}

// Ensure interceptor implements the necessary contracts.
var _ http.ResponseWriter = (*interceptor)(nil)
var _ http.Hijacker = (*interceptor)(nil)
var _ http.Flusher = (*interceptor)(nil)

// New creates a middleware Pipe that compresses HTTP responses using gzip
// with the specified options.
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
			// Skip if the client doesn't accept gzip compression.
			if !header.Accepts(r.Header.Get("Accept-Encoding"), "gzip") ||
				w.Header().Get("Content-Encoding") != "" {
				next.ServeHTTP(w, r)
				return
			}

			// Create the gzip response writer.
			gzw := &interceptor{
				ResponseWriter: w,
				level:          cfg.level,
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

// config holds the middleware configuration.
type config struct {
	level   int
	exclude []string
}

// Option is a function that configures the middleware.
type Option func(*config)

// WithCompressionLevel sets the compression level. It accepts values ranging
// from BestSpeed (1) to BestCompression (9). For other values, it will fall
// back to DefaultCompression, a good balance between speed and
// compression ratio.
func WithCompressionLevel(level int) Option {
	return func(c *config) {
		if level >= NoCompression && level <= BestCompression {
			c.level = level
		}
	}
}

// WithExcludeMimeTypes adds MIME types to the list of content types that
// should not be compressed. This option is additive and can be called
// multiple times; it appends to the default exclusion list rather than
// replacing it.
//
// The matching logic supports two formats:
//
//   - Exact: Provide the full MIME type (e.g., "application/pdf").
//   - Prefix: End the MIME type with a wildcard "*" (e.g., "image/*")
//     to exclude all subtypes for that primary type.
func WithExcludeMimeTypes(types ...string) Option {
	return func(c *config) {
		for _, t := range types {
			c.exclude = append(c.exclude, strings.ToLower(t))
		}
	}
}
