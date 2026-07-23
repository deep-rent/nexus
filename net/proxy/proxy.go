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
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/deep-rent/nexus/net/proxy/buffer"
	"github.com/deep-rent/nexus/sys/log"
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
		logger:          log.Discard(),
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
type ErrorHandlerFactory = func(*log.Logger) ErrorHandler

// NewErrorHandler is the default [ErrorHandlerFactory] for the proxy.
//
// It creates an error handler that logs upstream errors and maps them to
// appropriate HTTP status codes, while silencing client-initiated disconnects.
func NewErrorHandler(logger *log.Logger) ErrorHandler {
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
			logger.Error(
				r.Context(),
				"Upstream request timed out",
				log.String("method", method),
				log.String("uri", uri),
			)
		} else {
			logger.Error(
				r.Context(),
				"Upstream request failed",
				log.String("method", method),
				log.String("uri", uri),
				log.Err(err),
			)
		}

		w.WriteHeader(status)
	}
}
