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

// Package proxy provides a configurable reverse proxy handler.
//

package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/net/proxy/buffer"
)

const (
	// DefaultMinBufferSize is the default minimum size of pooled buffers (32
	// KiB).
	DefaultMinBufferSize = 32 << 10
	// DefaultMaxBufferSize is the default maximum size of pooled buffers (256
	// KiB).
	DefaultMaxBufferSize = 256 << 10
)

// Handler is an alias of [http.Handler] representing a reverse proxy.
type Handler = http.Handler

// NewHandler creates a new reverse proxy handler that routes to the target URL.
//
// The behavior of the proxy can be customized through the given options. It
// avoids the deprecated Director hook in favor of the modern Rewrite API.
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

// RewriteFunc defines a function to modify requests before they go upstream.
//
// The signature matches [httputil.ReverseProxy.Rewrite].
type RewriteFunc func(*httputil.ProxyRequest)

// RewriteFactory creates a [RewriteFunc] using the provided original
// [RewriteFunc].
//
// The returned [RewriteFunc] may call original to retain its behavior.
type RewriteFactory = func(original RewriteFunc) RewriteFunc

// NewRewrite is the default [RewriteFactory] for the proxy.
//
// It returns the original [RewriteFunc] unmodified. The default rewrite already
// sets X-Forwarded-Host, X-Forwarded-Proto, and X-Forwarded-For headers, and
// correctly rewrites the Host header to match the target.
func NewRewrite(original RewriteFunc) RewriteFunc {
	return original
}

// ErrorHandler defines a function for handling proxy operation errors.
//
// The signature matches [httputil.ReverseProxy.ErrorHandler].
type ErrorHandler = func(http.ResponseWriter, *http.Request, error)

// ErrorHandlerFactory creates an [ErrorHandler] using the provided logger.
//
// It receives the configured logger to be used for error reporting.
type ErrorHandlerFactory = func(*slog.Logger) ErrorHandler

// NewErrorHandler is the default [ErrorHandlerFactory] for the proxy.
//
// It creates an error handler that logs upstream errors and maps them to
// appropriate HTTP status codes, while silencing client-initiated disconnects.
func NewErrorHandler(logger *slog.Logger) ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			// Silence client-initiated disconnects; there's nothing useful to
			// send
			return
		}

		status := http.StatusBadGateway
		method, uri := r.Method, r.RequestURI

		if errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, http.ErrHandlerTimeout) {
			status = http.StatusGatewayTimeout
			logger.ErrorContext(
				r.Context(),
				"Upstream request timed out",
				slog.String("method", method),
				slog.String("uri", uri),
			)
		} else {
			logger.ErrorContext(
				r.Context(),
				"Upstream request failed",
				slog.String("method", method),
				slog.String("uri", uri),
				log.Err(err),
			)
		}

		w.WriteHeader(status)
	}
}

// handlerConfig holds the configurable settings for the proxy handler.
type handlerConfig struct {
	// transport handles the network communication with the upstream.
	transport *http.Transport
	// flushInterval is the periodic flush interval for response body copying.
	flushInterval time.Duration
	// minBufferSize is the minimum size of pooled buffers.
	minBufferSize int
	// maxBufferSize is the maximum size of pooled buffers.
	maxBufferSize int
	// newRewrite is the factory for creating the request rewrite function.
	newRewrite RewriteFactory
	// newErrorHandler is the factory for creating the error handling function.
	newErrorHandler ErrorHandlerFactory
	// logger is the structured logger for error reporting.
	logger *slog.Logger
}

// HandlerOption defines a function for setting reverse proxy options.
type HandlerOption func(*handlerConfig)

// WithTransport sets the [http.Transport] for upstream requests.
//
// Use this option to tune connection pooling, timeouts, and keep-alives. If nil
// is given, this option is ignored.
func WithTransport(t *http.Transport) HandlerOption {
	return func(cfg *handlerConfig) {
		if t != nil {
			cfg.transport = t
		}
	}
}

// WithFlushInterval specifies the periodic flush interval for the response.
//
// A zero value (default) disables periodic flushing. A negative value tells the
// proxy to flush immediately after each write. Adjust this if you observe high
// latencies for responses buffered by the proxy.
func WithFlushInterval(d time.Duration) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.flushInterval = d
	}
}

// WithMinBufferSize specifies the minimum size of pooled buffers.
//
// Non-positive values are ignored. The value will be capped at MaxBufferSize.
// Adapt this if you know from profiling that most responses are larger than the
// default 32 KiB.
func WithMinBufferSize(n int) HandlerOption {
	return func(cfg *handlerConfig) {
		if n > 0 {
			cfg.minBufferSize = n
		}
	}
}

// WithMaxBufferSize specifies the maximum size of buffers to be pooled.
//
// Buffers that grow larger than this size will be discarded after use to
// prevent memory bloat. If your P95 response size is larger than this value,
// the pool will be ineffective.
func WithMaxBufferSize(n int) HandlerOption {
	return func(cfg *handlerConfig) {
		if n > 0 {
			cfg.maxBufferSize = n
		}
	}
}

// WithRewrite provides a custom [RewriteFactory] for the proxy.
//
// If nil is given, this option is ignored. By default, [NewRewrite] is used.
func WithRewrite(f RewriteFactory) HandlerOption {
	return func(cfg *handlerConfig) {
		if f != nil {
			cfg.newRewrite = f
		}
	}
}

// WithErrorHandler provides a custom [ErrorHandlerFactory] for the proxy.
//
// If nil is given, this option is ignored. By default, [NewErrorHandler] is
// used.
func WithErrorHandler(f ErrorHandlerFactory) HandlerOption {
	return func(cfg *handlerConfig) {
		if f != nil {
			cfg.newErrorHandler = f
		}
	}
}

// WithLogger sets the logger to be used by the proxy's [ErrorHandler].
//
// If nil is given, this option is ignored. The default error handler uses this
// logger for capturing upstream errors.
func WithLogger(logger *slog.Logger) HandlerOption {
	return func(cfg *handlerConfig) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}
