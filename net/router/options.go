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

package router

import (
	"encoding/json/v2"
	"log/slog"
)

// Option defines a functional configuration option for the [Router].
type Option func(*Router)

// WithMiddleware adds global middleware to the [Router].
func WithMiddleware(mws ...Middleware) Option {
	return func(r *Router) {
		r.mws = append(r.mws, mws...)
	}
}

// WithMaxBodySize sets the maximum allowed size for request bodies.
func WithMaxBodySize(bytes int64) Option {
	return func(r *Router) {
		r.maxBytes = bytes
	}
}

// WithJSONOptions sets custom JSON options for the [Router].
func WithJSONOptions(opts ...json.Options) Option {
	return func(r *Router) {
		r.jsonOpts = opts
	}
}

// WithErrorHandler sets a custom error handler.
func WithErrorHandler(h ErrorHandler) Option {
	return func(r *Router) {
		if h != nil {
			r.errorHandler = h
		}
	}
}

// WithLogger updates the default error handler to use the given logger.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Router) {
		if logger != nil {
			r.errorHandler = defaultErrorHandler(logger)
		}
	}
}
