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

// Package cors provides a configurable CORS middleware for http.Handlers.
//
// It implements Cross-Origin Resource Sharing for [http.Handler] instances:
// preflight (OPTIONS) requests are handled and terminated automatically, and
// the appropriate CORS headers are injected into responses for actual
// requests.
//
// Requests without an Origin header, and requests from origins outside the
// configured whitelist, pass through to the next handler without CORS
// headers; the browser then blocks cross-origin access on the client side.
//
// # Usage
//
// The [New] function creates the middleware pipe, which can be configured with
// functional options (e.g., [WithAllowedOrigins], [WithAllowedMethods]).
//
// Example:
//
//	// Configure CORS to allow requests from a specific origin with
//	// restricted methods and additional headers.
//	pipe := cors.New(
//	  cors.WithAllowedOrigins("https://example.com"),
//	  cors.WithAllowedMethods(http.MethodGet, http.MethodOptions),
//	  cors.WithAllowedHeaders("Authorization", "Content-Type"),
//	  cors.WithMaxAge(12*time.Hour),
//	)
//
//	handler := http.HandlerFunc( ... )
//	// Apply the CORS middleware as one of the first layers.
//	chainedHandler := middleware.Chain(handler, pipe)
//
//	http.ListenAndServe(":8080", chainedHandler)
package cors

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/middleware"
)

// wildcard is a special value that can be passed in configuration to allow
// requests from any origin.
const wildcard = "*"

// config stores the pre-computed configuration for internal use.
type config struct {
	// allowedOrigins is the whitelist of permitted Origin values.
	allowedOrigins map[string]struct{}
	// allowedMethods is the pre-joined string for Access-Control-Allow-Methods.
	allowedMethods string
	// allowedHeaders is the pre-joined string for Access-Control-Allow-Headers.
	allowedHeaders string
	// exposedHeaders is the pre-joined string for
	// Access-Control-Expose-Headers.
	exposedHeaders string
	// allowCredentials maps to the Access-Control-Allow-Credentials header.
	allowCredentials bool
	// maxAge is the string representation of Access-Control-Max-Age in seconds.
	maxAge string
}

// Option is a function that configures the CORS middleware.
type Option func(*config)

// WithAllowedOrigins sets the allowed origins for CORS requests.
//
// By default, all origins are allowed. The same behavior can be achieved by
// leaving the list empty or by manually including the special wildcard "*". In
// other cases, this option restricts requests to a specific whitelist. If
// credentials are enabled via [WithAllowCredentials], browsers forbid a
// wildcard origin, and this middleware will dynamically reflect the request's
// Origin header if it is in the allowed list.
//
// Origins are compared byte-for-byte against the browser-supplied Origin
// header, so list them exactly as browsers serialize them: lowercase scheme
// and host, no trailing slash, and no port for scheme defaults (e.g.
// "https://app.example.com" or "http://localhost:3000").
func WithAllowedOrigins(origins ...string) Option {
	return func(c *config) {
		if len(origins) != 0 && !slices.Contains(origins, wildcard) {
			c.allowedOrigins = make(map[string]struct{}, len(origins))
			for _, origin := range origins {
				c.allowedOrigins[origin] = struct{}{}
			}
		}
	}
}

// WithAllowedMethods sets the allowed HTTP methods for CORS requests.
//
// If no methods are provided, this header is omitted by default, and only
// simple methods (GET, POST, HEAD) are implicitly allowed by browsers for
// non-preflighted requests. It is recommended to list all methods your API
// supports, including OPTIONS.
func WithAllowedMethods(methods ...string) Option {
	return func(c *config) {
		if len(methods) != 0 {
			c.allowedMethods = strings.Join(methods, ", ")
		}
	}
}

// WithAllowedHeaders sets the allowed HTTP headers for CORS requests.
//
// This is necessary for any non-standard headers the client needs to send,
// such as "Authorization" or custom "X-" headers. If not set, browsers will
// only permit requests with CORS-safelisted request headers.
func WithAllowedHeaders(headers ...string) Option {
	return func(c *config) {
		if len(headers) != 0 {
			c.allowedHeaders = strings.Join(headers, ", ")
		}
	}
}

// WithExposedHeaders sets the HTTP headers safe to expose to the API.
//
// By default, client-side scripts can only access a limited set of simple
// response headers. This option lists additional headers (like a custom
// "X-Pagination-Total" header) that should be made accessible to the script.
func WithExposedHeaders(headers ...string) Option {
	return func(c *config) {
		if len(headers) != 0 {
			c.exposedHeaders = strings.Join(headers, ", ")
		}
	}
}

// WithAllowCredentials indicates if the response can be exposed with
// credentials.
//
// When used as part of a response to a preflight request, it indicates that the
// actual request can include cookies and other user credentials. This option
// defaults to false. Note that browsers require a specific origin (not a
// wildcard) in the Access-Control-Allow-Origin header when this is enabled;
// consequently, [New] panics if credentials are enabled without an explicit
// origin whitelist configured via [WithAllowedOrigins].
func WithAllowCredentials(allow bool) Option {
	return func(c *config) {
		c.allowCredentials = allow
	}
}

// WithMaxAge indicates how long preflight results can be cached, in seconds.
//
// If set to 0 (the default), the header is omitted. Be aware that browsers
// have a default internal limit (usually 5 seconds) when this header is
// missing. This results in a preflight request for almost every API call, which
// can double the traffic to your server. It is recommended to set this to a
// higher value (e.g., 10 minutes) for stable APIs to reduce latency.
func WithMaxAge(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.maxAge = strconv.FormatInt(int64(d.Seconds()), 10)
		}
	}
}

// New creates a middleware [middleware.Pipe] that handles CORS requests.
//
// The middleware distinguishes between preflight and actual requests. Preflight
// (OPTIONS) requests are intercepted and terminated with a 204 No Content
// response. For actual requests, it adds the necessary CORS headers to the
// response before passing control to the next handler. Non-CORS requests are
// passed through without modification.
//
// It panics if credentials are enabled without an explicit origin whitelist:
// reflecting arbitrary origins alongside Access-Control-Allow-Credentials
// would let any website perform authenticated requests on behalf of visiting
// users and read the responses.
func New(opts ...Option) middleware.Pipe {
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.allowCredentials && cfg.allowedOrigins == nil {
		panic("cors: credentials require explicit allowed origins")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if proceed := handle(&cfg, w, r); proceed {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// handle processes CORS headers for the given request.
//
// It returns true if the request should be passed to the next handler. It
// returns false if the request has been fully handled, such as in a preflight
// request.
func handle(cfg *config, w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	// Pass through non-CORS requests.
	if origin == "" {
		return true
	}

	// Apply this header immediately to ensure caches respect the difference
	// between allowed and disallowed origin responses.
	h := w.Header()
	h.Add("Vary", "Origin")

	preflight := r.Method == http.MethodOptions
	// Pass through invalid preflight requests.
	if preflight && r.Header.Get("Access-Control-Request-Method") == "" {
		return true
	}
	if preflight {
		// Preflight responses also depend on the requested method and
		// headers, so caches must key on them as well.
		h.Add("Vary", "Access-Control-Request-Method")
		h.Add("Vary", "Access-Control-Request-Headers")
	}
	// Validate origin if not in wildcard mode.
	if cfg.allowedOrigins != nil {
		if _, ok := cfg.allowedOrigins[origin]; !ok {
			return true // Let non-matching origins pass through without CORS headers.
		}
	}

	if !cfg.allowCredentials && cfg.allowedOrigins == nil {
		origin = wildcard
	}

	h.Set("Access-Control-Allow-Origin", origin)
	if cfg.allowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}

	// Handle preflight requests.
	if preflight {
		if cfg.allowedMethods != "" {
			h.Set("Access-Control-Allow-Methods", cfg.allowedMethods)
		}
		if cfg.allowedHeaders != "" {
			h.Set("Access-Control-Allow-Headers", cfg.allowedHeaders)
		}
		if cfg.maxAge != "" {
			h.Set("Access-Control-Max-Age", cfg.maxAge)
		}
		w.WriteHeader(http.StatusNoContent)
		return false // Terminate request chain.
	}

	// Handle actual requests.
	if cfg.exposedHeaders != "" {
		h.Set("Access-Control-Expose-Headers", cfg.exposedHeaders)
	}
	return true
}
