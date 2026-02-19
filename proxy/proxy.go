// Package proxy provides a configurable reverse proxy handler. It constructs an
// httputil.ReverseProxy, starting with sensible defaults, integrating a
// reusable buffer pool, structured logging, and robust error handling
// via a functional options API.
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
		transport:       http.DefaultTransport.(*http.Transport).Clone(),
		flushInterval:   0,
		minBufferSize:   DefaultMinBufferSize,
		maxBufferSize:   DefaultMaxBufferSize,
		newRewrite:      NewRewrite,
		newErrorHandler: NewErrorHandler,
		logger:          slog.Default(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.minBufferSize > cfg.maxBufferSize {
		cfg.minBufferSize = cfg.maxBufferSize
	}

	// Construct ReverseProxy directly to avoid the deprecated Director hook
	// set by NewSingleHostReverseProxy.
	h := &httputil.ReverseProxy{
		ErrorHandler:  cfg.newErrorHandler(cfg.logger),
		Transport:     cfg.transport,
		BufferPool:    buffer.NewPool(cfg.minBufferSize, cfg.maxBufferSize),
		FlushInterval: cfg.flushInterval,
	}

	defaultRewrite := func(pr *httputil.ProxyRequest) {
		pr.SetXForwarded()
		pr.SetURL(target)
	}

	h.Rewrite = cfg.newRewrite(defaultRewrite)

	return h
}

// RewriteFunc defines a function to modify the proxy request before it is sent
// to the upstream target.
//
// The signature matches httputil.ReverseProxy.Rewrite.
type RewriteFunc func(*httputil.ProxyRequest)

// RewriteFactory creates a RewriteFunc using the provided original RewriteFunc.
// The returned RewriteFunc may call original to retain its behavior.
type RewriteFactory = func(original RewriteFunc) RewriteFunc

// NewRewrite is the default RewriteFactory for the proxy.
// It returns the original RewriteFunc unmodified.
func NewRewrite(original RewriteFunc) RewriteFunc {
	// The default rewrite need not be overridden; it already sets the
	// X-Forwarded-Host, X-Forwarded-Proto, and X-Forwarded-For headers, which is
	// exactly what most proxies expect. It also correctly rewrites the Host header
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
	transport       *http.Transport
	flushInterval   time.Duration
	minBufferSize   int
	maxBufferSize   int
	newRewrite      RewriteFactory
	newErrorHandler ErrorHandlerFactory
	logger          *slog.Logger
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

// WithMaxBufferSize specifies the maximum size of buffers to be returned to
// the buffer pool. Buffers that grow larger than this size will be discarded
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

// WithRewrite provides a custom RewriteFactory for the proxy.
//
// If nil is given, this option is ignored. By default, NewRewrite is used.
func WithRewrite(f RewriteFactory) HandlerOption {
	return func(cfg *handlerConfig) {
		if f != nil {
			cfg.newRewrite = f
		}
	}
}

// WithErrorHandler provides a custom ErrorHandlerFactory for the proxy.
//
// If nil is given, this option is ignored. By default, NewErrorHandler is used.
func WithErrorHandler(f ErrorHandlerFactory) HandlerOption {
	return func(cfg *handlerConfig) {
		if f != nil {
			cfg.newErrorHandler = f
		}
	}
}

// WithLogger sets the logger to be used by the proxy's ErrorHandler.
//
// If nil is given, this option is ignored. By default, slog.Default() is used.
// The default error handler (NewErrorHandler) uses this logger for capturing
// upstream errors.
func WithLogger(log *slog.Logger) HandlerOption {
	return func(cfg *handlerConfig) {
		if log != nil {
			cfg.logger = log
		}
	}
}
