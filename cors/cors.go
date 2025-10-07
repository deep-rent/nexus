// Package cors provides a configurable CORS (Cross-Origin Resource Sharing)
// middleware handler.
package cors

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/middleware"
)

// Wildcard is a special value that can be passed in configuration to allow
// requests from any origin.
const Wildcard = "*"

// config stores the pre-computed configuration for internal use.
type config struct {
	AllowedOrigins   map[string]struct{}
	AllowedMethods   string
	AllowedHeaders   string
	ExposedHeaders   string
	AllowCredentials bool
	MaxAge           string
}

// Option is a function that configures the CORS middleware.
type Option func(*config)

// WithAllowedOrigins sets the allowed origins for CORS requests. If no origins
// are provided, this option has no effect. Otherwise this option overrides any
// previously set values. By default, the middleware allows requests from any
// origin. The same behavior can be achieved by leaving the list empty or by
// including the special Wildcard "*".
func WithAllowedOrigins(origins ...string) Option {
	return func(c *config) {
		if len(origins) != 0 && !slices.Contains(origins, Wildcard) {
			c.AllowedOrigins = make(map[string]struct{}, len(origins))
			for _, origin := range origins {
				c.AllowedOrigins[origin] = struct{}{}
			}
		}
	}
}

// WithAllowedMethods sets the allowed HTTP methods for CORS requests.
// If no methods are provided, this option has no effect. Otherwise this option
// overrides any previously set values. By default, the middleware omits the
// corresponding header. Recommended methods include "GET", "HEAD", "POST",
// "PUT", "PATCH", "DELETE", and "OPTIONS".
func WithAllowedMethods(methods ...string) Option {
	return func(c *config) {
		if len(methods) != 0 {
			c.AllowedMethods = strings.Join(methods, ", ")
		}
	}
}

// WithAllowedHeaders sets the allowed HTTP headers for CORS requests. By
// default, only CORS-safelisted headers are allowed. Any additional headers
// the client needs to send (e.g., "Authorization", "Content-Type") must be
// explicitly listed here.
func WithAllowedHeaders(headers ...string) Option {
	return func(c *config) {
		if len(headers) != 0 {
			c.AllowedHeaders = strings.Join(headers, ", ")
		}
	}
}

// WithExposedHeaders sets the HTTP headers that are safe to expose to the
// API of a CORS API specification. If no headers are provided, this option has
// no effect. Otherwise this option overrides any previously set values. By
// default, the middleware omits the corresponding header.
func WithExposedHeaders(headers ...string) Option {
	return func(c *config) {
		if len(headers) != 0 {
			c.ExposedHeaders = strings.Join(headers, ", ")
		}
	}
}

// WithAllowCredentials indicates whether the response to the request can be
// exposed when the credentials flag is true. When used as part of a response to
// a preflight request, it indicates that the actual request can include user
// credentials. This option defaults to false.
func WithAllowCredentials(allow bool) Option {
	return func(c *config) {
		c.AllowCredentials = allow
	}
}

// WithMaxAge indicates how long the results of a preflight request can be
// cached. This option defaults to 0, which means no max age is set. Reasonable
// values range from a few minutes to a full day, depending on how often the
// CORS policy changes.
func WithMaxAge(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.MaxAge = strconv.FormatInt(int64(d.Seconds()), 10)
		}
	}
}

// New creates a middleware Pipe that handles CORS based on the provided
// configuration.
//
// It intercepts and terminates preflight (OPTIONS) requests with a 204 (No
// Content) status, preventing them from reaching downstream handlers. For all
// other (actual) requests, it adds the necessary CORS headers to the response
// before passing the request on to the next handler in the chain.
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
	origin := r.Header.Get(header.Origin)
	// Pass through non-CORS requests.
	if origin == "" {
		return true
	}
	preflight := r.Method == http.MethodOptions
	// Pass through invalid preflight requests.
	if preflight && r.Header.Get(header.AccessControlRequestMethod) == "" {
		return true
	}
	// Validate origin if not in wildcard mode.
	if cfg.AllowedOrigins != nil {
		if _, ok := cfg.AllowedOrigins[origin]; !ok {
			return true // Let non-matching origins pass through without CORS headers.
		}
	}

	h := w.Header()
	h.Add(header.Vary, header.Origin)
	if !cfg.AllowCredentials && cfg.AllowedOrigins == nil {
		origin = Wildcard
	}
	h.Set(header.AccessControlAllowOrigin, origin)
	if cfg.AllowCredentials {
		h.Set(header.AccessControlAllowCredentials, "true")
	}

	// Handle preflight requests.
	if preflight {
		if cfg.AllowedMethods != "" {
			h.Set(header.AccessControlAllowMethods, cfg.AllowedMethods)
		}
		if cfg.AllowedHeaders != "" {
			h.Set(header.AccessControlAllowHeaders, cfg.AllowedHeaders)
		}
		if cfg.MaxAge != "" {
			h.Set(header.AccessControlMaxAge, cfg.MaxAge)
		}
		w.WriteHeader(http.StatusNoContent)
		return false // Terminate request chain.
	}

	// Handle actual requests.
	if cfg.ExposedHeaders != "" {
		h.Set(header.AccessControlExposeHeaders, cfg.ExposedHeaders)
	}
	return true
}
