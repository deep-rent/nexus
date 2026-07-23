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

package proxy

import (
	"net/http"
	"time"

	"github.com/deep-rent/nexus/sys/log"
)

const (
	// DefaultMinBufferSize is the default minimum size of pooled buffers (32
	// KiB).
	DefaultMinBufferSize = 32 << 10
	// DefaultMaxBufferSize is the default maximum size of pooled buffers (256
	// KiB).
	DefaultMaxBufferSize = 256 << 10
)

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
	logger *log.Logger
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

// WithLogger sets the [log.Logger] to be used by the proxy's
// [ErrorHandler].
//
// If nil is given, this option is ignored. The default error handler uses
// this logger for capturing upstream errors; without one, errors stay
// silent ([log.Discard]).
func WithLogger(logger *log.Logger) HandlerOption {
	return func(cfg *handlerConfig) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}
