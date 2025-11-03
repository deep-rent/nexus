// Package proxy provides a configurable reverse proxy handler. It wraps
// httputil.NewSingleHostReverseProxy, starting with sensible defaults,
// integrating a reusable buffer pool, structured logging, and robust error
// handling via a functional options API.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/internal/buffer"
)

const (
	// DefaultMinBufferSize is the default minimum size of pooled buffers.
	DefaultMinBufferSize = 32 << 10 // 32 KiB
	// DefaultMaxBufferSize is the default maximum size of pooled buffers.
	DefaultMaxBufferSize = 256 << 10 // 256 KiB
)

// Handler is an alias of http.Handler representing a reverse proxy.
type Handler = http.Handler

// NewHandler creates a new reverse proxy handler that routes to the target URL.
// The behavior of the proxy can be customized through the given options.
func NewHandler(target *url.URL, opts ...HandlerOption) Handler {
	cfg := handlerConfig{
		transport:     &http.Transport{},
		flushInterval: 0,
		minBufferSize: DefaultMinBufferSize,
		maxBufferSize: DefaultMaxBufferSize,
		director:      NewDirector,
		errorHandler:  NewErrorHandler,
		logger:        slog.Default(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	h := httputil.NewSingleHostReverseProxy(target)
	h.ErrorHandler = cfg.errorHandler(cfg.logger)
	h.Transport = cfg.transport
	h.FlushInterval = cfg.flushInterval
	h.BufferPool = buffer.NewPool(cfg.minBufferSize, cfg.maxBufferSize)
	h.Director = cfg.director(h.Director)

	return h
}

// Director defines a function to modify the request before it is sent to the
// upstream target.
//
// The signature matches httputil.ReverseProxy.Director.
type Director func(*http.Request)

// DirectorFactory creates a Director using the provided original Director.
// The returned Director may call original to retain its behavior.
type DirectorFactory = func(original Director) Director

// NewDirector is the default DirectorFactory for the proxy.
// It returns the original Director unmodified.
func NewDirector(original Director) Director {
	// The default director need not be overridden; it already sets the
	// X-Forwarded-Host and X-Forwarded-Proto headers, which is exactly
	// what most proxies expect. It also correctly rewrites the Host header
	// to match the target (required for sidecar setups to function).
	return original
}

// ErrorHandler defines a function for handling errors that occur during the
// reverse proxy's operation.
//
// The signature matches httputil.ReverseProxy.ErrorHandler.
type ErrorHandler = func(http.ResponseWriter, *http.Request, error)

// ErrorHandlerFactory creates an ErrorHandler using the provided logger.
// It receives the configured logger to be used for error reporting.
type ErrorHandlerFactory = func(*slog.Logger) ErrorHandler

// NewErrorHandler is the default ErrorHandlerFactory for the proxy.
// It creates an error handler that logs upstream errors using
// the provided logger and maps them to appropriate HTTP status codes.
func NewErrorHandler(logger *slog.Logger) ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			// Silence client-initiated disconnects; there's nothing useful to send
			return
		}

		status := http.StatusBadGateway
		method, uri := r.Method, r.RequestURI

		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
			logger.Error(
				"Upstream request timed out",
				slog.String("method", method),
				slog.String("uri", uri),
			)
		} else {
			logger.Error(
				"Upstream request failed",
				slog.String("method", method),
				slog.String("uri", uri),
				slog.Any("error", err),
			)
		}

		w.WriteHeader(status)
	}
}

// handlerConfig holds the configurable settings for the proxy handler.
type handlerConfig struct {
	transport     *http.Transport
	flushInterval time.Duration
	minBufferSize int
	maxBufferSize int
	director      DirectorFactory
	errorHandler  ErrorHandlerFactory
	logger        *slog.Logger
}

// HandlerOption defines a function for setting reverse proxy options.
type HandlerOption func(*handlerConfig)

// WithTransport sets the http.Transport for upstream requests.
//
// Use this option to tune connection pooling, timeouts (e.g., Dial,
// TLSHandshake), and keep-alives. If nil is given, this option is ignored.
func WithTransport(t *http.Transport) HandlerOption {
	return func(cfg *handlerConfig) {
		if t != nil {
			cfg.transport = t
		}
	}
}

// WithFlushInterval specifies the periodic flush interval for copying the
// response body to the client.
//
// A zero value (default) disables periodic flushing. A negative value tells
// the proxy to flush immediately after each write to the client. The proxy is
// smart enough to recognize streaming responses, ignoring the flush interval
// in such cases.
//
// Adjust this setting if you observe high latencies for responses that are
// fully buffered by the proxy before being sent to the client. A lower value
// reduces latency at the cost of increased CPU usage.
func WithFlushInterval(d time.Duration) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.flushInterval = d
	}
}

// WithMinBufferSize specifies the minimum size of buffers allocated by the
// buffer pool. This helps to reduce allocations for large response bodies.
//
// Non-positive values are ignored, and DefaultMinBufferSize is used. The
// value will be capped at MaxBufferSize.
//
// The pool will automatically adjust itself for larger, common responses
// and the MaxBufferSize will protect from memory bloat. You only need to
// adapt this setting if you know from profiling that 99% of your responses
// are, for example, larger than 100 KB.
func WithMinBufferSize(n int) HandlerOption {
	return func(cfg *handlerConfig) {
		if n > 0 {
			cfg.minBufferSize = n
		}
	}
}

// WithMaxBufferSize specifies the maximum size of buffers to keep in the
// buffer pool. Buffers that grow larger than this size will be discarded
// after use to prevent memory bloat.
//
// Non-positive values are ignored, and DefaultMaxBufferSize is used.
//
// This is a critical tuning parameter. If your typical (e.g., P95)
// response size is larger than this value, the pool will be
// ineffective, as most buffers will be discarded instead of being reused.
func WithMaxBufferSize(n int) HandlerOption {
	return func(cfg *handlerConfig) {
		if n > 0 {
			cfg.maxBufferSize = n
		}
	}
}

// WithDirector provides a custom DirectorFactory for the proxy.
//
// If nil is given, this option is ignored. By default, NewDirector is used.
func WithDirector(f DirectorFactory) HandlerOption {
	return func(cfg *handlerConfig) {
		if f != nil {
			cfg.director = f
		}
	}
}

// WithErrorHandler provides a custom ErrorHandlerFactory for the proxy.
//
// If nil is given, this option is ignored. By default, NewErrorHandler is used.
func WithErrorHandler(f ErrorHandlerFactory) HandlerOption {
	return func(cfg *handlerConfig) {
		if f != nil {
			cfg.errorHandler = f
		}
	}
}

// WithLogger sets the logger to be used by the proxy's ErrorHandler.
//
// If nil is given, this option is ignored. By default, slog.Default() is used.
func WithLogger(log *slog.Logger) HandlerOption {
	return func(cfg *handlerConfig) {
		if log != nil {
			cfg.logger = log
		}
	}
}
