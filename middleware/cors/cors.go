// Package cors provides a configurable CORS (Cross-Origin Resource Sharing)
// middleware for http.Handlers.
//
// # Usage
//
// The New function creates the middleware pipe, which can be configured with
// functional options (e.g., WithAllowedOrigins, WithAllowedMethods). The
// middleware automatically handles preflight (OPTIONS) requests and injects the
// appropriate CORS headers into responses for actual requests.
//
// Example:
//
//	// Configure CORS to allow requests from a specific origin with
//	// restricted methods and additional headers.
//	pipe := cors.New(
//		cors.WithAllowedOrigins("https://example.com"),
//		cors.WithAllowedMethods(http.MethodGet, http.MethodOptions),
//		cors.WithAllowedHeaders("Authorization", "Content-Type"),
//		cors.WithMaxAge(12*time.Hour),
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
	allowedOrigins   map[string]struct{}
	allowedMethods   string
	allowedHeaders   string
	exposedHeaders   string
	allowCredentials bool
	maxAge           string
}

// Option is a function that configures the CORS middleware.
type Option func(*config)

// WithAllowedOrigins sets the allowed origins for CORS requests.
//
// By default, all origins are allowed. The same behavior can be achieved by
// leaving the list empty or by manually including the special wildcard "*".
// In other cases, this option restricts requests to a specific whitelist. If
// credentials are enabled via WithAllowCredentials, browsers forbid a wildcard
// origin, and this middleware will dynamically reflect the request's Origin
// header if it is in the allowed list.
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

// WithExposedHeaders sets the HTTP headers that are safe to expose to the
// API of a CORS API specification.
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

// WithAllowCredentials indicates whether the response to the request can be
// exposed when the credentials flag is true.
//
// When used as part of a response to a preflight request, it indicates that the
// actual request can include cookies and other user credentials. This option
// defaults to false. Note that browsers require a specific origin (not a
// wildcard) in the Access-Control-Allow-Origin header when this is enabled.
func WithAllowCredentials(allow bool) Option {
	return func(c *config) {
		c.allowCredentials = allow
	}
}

// WithMaxAge indicates how long the results of a preflight request can be
// cached by the browser, in seconds.
//
// A duration of 0 or less omits the header. Caching preflight responses can
// significantly reduce latency for clients making multiple different requests.
func WithMaxAge(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.maxAge = strconv.FormatInt(int64(d.Seconds()), 10)
		}
	}
}

// New creates a middleware Pipe that handles CORS based on the provided
// options.
//
// The middleware distinguishes between preflight and actual requests. Preflight
// (OPTIONS) requests are intercepted and terminated with a 204 No Content
// response. For actual requests, it adds the necessary CORS headers to the
// response before passing control to the next handler. Non-CORS requests are
// passed through without modification.
func New(opts ...Option) middleware.Pipe {
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if proceed := handle(&cfg, w, r); proceed {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// handle processes CORS headers and returns true if the request should
// be passed to the next handler. It returns false if the request has been
// fully handled, such as in a preflight request.
func handle(cfg *config, w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	// Pass through non-CORS requests.
	if origin == "" {
		return true
	}
	preflight := r.Method == http.MethodOptions
	// Pass through invalid preflight requests.
	if preflight && r.Header.Get("Access-Control-Request-Method") == "" {
		return true
	}
	// Validate origin if not in wildcard mode.
	if cfg.allowedOrigins != nil {
		if _, ok := cfg.allowedOrigins[origin]; !ok {
			return true // Let non-matching origins pass through without CORS headers.
		}
	}

	h := w.Header()
	h.Add("Vary", "Origin")
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
