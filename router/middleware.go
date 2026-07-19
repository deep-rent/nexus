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
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/middleware/cors"
	"github.com/deep-rent/nexus/middleware/gzip"
	"golang.org/x/time/rate"
)

// Middleware defines a function that wraps a [Handler].
//
// It allows custom logic to be executed before and/or after the next handler.
// Unlike standard HTTP middleware, this natively supports returning API errors.
type Middleware func(Handler) Handler

// Chain combines a handler with multiple [Middleware] functions.
//
// The functions are applied in reverse order, meaning the first middleware in
// the list is the outermost and executes first.
func Chain(h Handler, mws ...Middleware) Handler {
	for _, mw := range slices.Backward(mws) {
		if mw != nil {
			h = mw(h)
		}
	}
	return h
}

// Wrap converts a standard [http.Handler] into a router [Handler].
func Wrap(h http.Handler) Handler {
	return HandlerFunc(func(e *Exchange) error {
		h.ServeHTTP(e.W, e.R)
		return nil
	})
}

// Adapt converts a standard [middleware.Pipe] into a [Middleware].
//
// This bridges low-level HTTP transport middlewares into the router's
// ecosystem. It ensuring that any modifications made to the request or response
// writer by the transport middleware are preserved.
func Adapt(pipe middleware.Pipe) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(e *Exchange) error {
			var nextErr error

			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				e.R = r
				if rw, ok := w.(ResponseWriter); ok {
					e.W = rw
				} else {
					e.W = NewResponseWriter(w)
				}

				nextErr = next.ServeHTTP(e)

				// Resolve the error immediately so transport middlewares
				// (like Logger) observe the correct HTTP status code.
				if nextErr != nil && e.errorHandler != nil {
					e.errorHandler(e, nextErr)
					nextErr = nil // Prevent double-handling upstream
				}
			})

			pipe(h).ServeHTTP(e.W, e.R)
			return nextErr
		})
	}
}

// Recover mirrors [middleware.Recover] for use in the router.
func Recover(logger *slog.Logger) Middleware {
	return Adapt(middleware.Recover(logger))
}

// RequestID mirrors [middleware.RequestID] for use in the router.
func RequestID() Middleware {
	return Adapt(middleware.RequestID())
}

// Log mirrors [middleware.Log] for use in the router.
func Log(logger *slog.Logger) Middleware {
	return Adapt(middleware.Log(logger))
}

// Volatile mirrors [middleware.Volatile] for use in the router.
func Volatile() Middleware {
	return Adapt(middleware.Volatile())
}

// Secure mirrors [middleware.Secure] for use in the router.
func Secure(cfg middleware.SecurityConfig) Middleware {
	return Adapt(middleware.Secure(cfg))
}

// CORS mirrors the middleware created by [cors.New] for use in the router.
func CORS(opts ...cors.Option) Middleware {
	return Adapt(cors.New(opts...))
}

// Gzip mirrors the middleware created by [gzip.New] for use in the router.
func Gzip(opts ...gzip.Option) Middleware {
	return Adapt(gzip.New(opts...))
}

// RateLimit returns a [Middleware] that applies global rate limiting
// using the provided [rate.Limiter].
//
// If the limit is exceeded, it halts the chain and returns a [*Error] with
// status 429 Too Many Requests. For more complex strategies like per-client
// or per-IP limiting, use [RateLimitFunc].
func RateLimit(limiter *rate.Limiter) Middleware {
	return RateLimitFunc(func(*http.Request) *rate.Limiter {
		return limiter
	})
}

// RateLimitFunc returns a [Middleware] that applies rate limiting using a
// dynamic [rate.Limiter] resolved per-request.
//
// The supplier callback allows callers to implement arbitrary rate limiting
// policies (e.g., per-IP, per-user, or tiered limits). If the callback returns
// nil, the request proceeds without rate limiting. If the limit is exceeded,
// it returns a [*Error] with status 429 Too Many Requests.
func RateLimitFunc(supply func(*http.Request) *rate.Limiter) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(e *Exchange) error {
			if limiter := supply(e.R); limiter != nil {
				res := limiter.Reserve()
				if !res.OK() {
					return &Error{
						Status:      http.StatusTooManyRequests,
						Reason:      ReasonRateLimit,
						Description: "The rate limit has been exceeded.",
					}
				}
				if delay := res.Delay(); delay > 0 {
					res.Cancel()
					sec := int(math.Ceil(delay.Seconds()))
					e.W.Header().Set("Retry-After", strconv.Itoa(sec))
					return &Error{
						Status: http.StatusTooManyRequests,
						Reason: ReasonRateLimit,
						Description: "The rate limit has been exceeded." +
							" Try again later.",
					}
				}
			}
			return next.ServeHTTP(e)
		})
	}
}
