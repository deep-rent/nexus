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

// Default CORS configuration values.
const (
	Wildcard                = "*"
	DefaultAllowCredentials = true
	DefaultMaxAge           = 12 * time.Hour
)

// Config defines configuration options for the CORS middleware.
type Config struct {
	// AllowedOrigins specifies the list of origins that are allowed to access
	// the resource. If empty or contains Wildcard (*), all origins are allowed.
	AllowedOrigins []string
	// AllowedMethods specifies the list of HTTP methods the client is allowed
	// to use. Defaults to DELETE, GET, HEAD, OPTIONS, PATCH, POST and PUT.
	AllowedMethods []string
	// AllowedHeaders specifies the list of non-standard headers the client is
	// allowed to send. An empty list defaults to the browser's safelist.
	AllowedHeaders []string
	// ExposedHeaders specifies the list of headers in the response that can be
	// exposed to the client's browser.
	ExposedHeaders []string
	// AllowCredentials indicates whether the response can be exposed to the
	// browser when the credentials flag is true.
	AllowCredentials bool
	// MaxAge indicates how long the results of a preflight request can be
	// cached by the browser.
	MaxAge time.Duration
}

// DefaultConfig returns a new Config with sensible, permissive defaults
// suitable for many common use cases.
func DefaultConfig() Config {
	defaultAllowedOrigins := []string{Wildcard}
	defaultAllowedMethods := []string{
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
	}
	return Config{
		AllowedOrigins:   defaultAllowedOrigins,
		AllowedMethods:   defaultAllowedMethods,
		AllowCredentials: DefaultAllowCredentials,
		MaxAge:           DefaultMaxAge,
	}
}

// config stores the pre-computed configuration for internal use.
type config struct {
	AllowedOrigins   map[string]struct{}
	AllowedMethods   string
	AllowedHeaders   string
	ExposedHeaders   string
	AllowCredentials bool
	MaxAge           string
}

// compile processes the user-facing Config into an optimized internal format.
func compile(cfg Config) config {
	c := config{
		AllowedOrigins:   nil,
		AllowCredentials: cfg.AllowCredentials,
		AllowedMethods:   strings.Join(cfg.AllowedMethods, ", "),
		AllowedHeaders:   strings.Join(cfg.AllowedHeaders, ", "),
		ExposedHeaders:   strings.Join(cfg.ExposedHeaders, ", "),
	}
	if cfg.MaxAge > 0 {
		c.MaxAge = strconv.FormatInt(int64(cfg.MaxAge.Seconds()), 10)
	}
	if len(cfg.AllowedOrigins) != 0 ||
		slices.Contains(cfg.AllowedOrigins, Wildcard) {
		c.AllowedOrigins = make(map[string]struct{}, len(cfg.AllowedOrigins))
		for _, origin := range cfg.AllowedOrigins {
			c.AllowedOrigins[origin] = struct{}{}
		}
	}
	return c
}

// New creates a middleware Pipe that handles CORS based on the provided
// configuration.
//
// It intercepts and terminates preflight (OPTIONS) requests with a 204 (No
// Content) status, preventing them from reaching downstream handlers. For all
// other (actual) requests, it adds the necessary CORS headers to the response
// before passing the request on to the next handler in the chain.
func New(cfg Config) middleware.Pipe {
	c := compile(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get(header.Origin)
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			if c.AllowedOrigins != nil {
				if _, ok := c.AllowedOrigins[origin]; !ok {
					next.ServeHTTP(w, r)
					return
				}
			}
			h := w.Header()
			h.Add(header.Vary, header.Origin)
			if c.AllowCredentials {
				h.Set(header.AccessControlAllowOrigin, origin)
				h.Set(header.AccessControlAllowCredentials, "true")
			} else if c.AllowedOrigins == nil {
				h.Set(header.AccessControlAllowOrigin, Wildcard)
			} else {
				h.Set(header.AccessControlAllowOrigin, origin)
			}
			if IsPreflight(r) {
				if c.AllowedMethods != "" {
					h.Set(header.AccessControlAllowMethods, c.AllowedMethods)
				}
				if c.AllowedHeaders != "" {
					h.Set(header.AccessControlAllowHeaders, c.AllowedHeaders)
				}
				if c.MaxAge != "" {
					h.Set(header.AccessControlMaxAge, c.MaxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			} else {
				if c.ExposedHeaders != "" {
					h.Set(header.AccessControlExposeHeaders, c.ExposedHeaders)
				}
				next.ServeHTTP(w, r)
				return
			}
		})
	}
}

// IsPreflight checks if the request is a CORS preflight request.
// This is a useful utility for middleware that may need to detect but not
// fully handle a preflight request, such as in a proxy scenario.
func IsPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get(header.AccessControlRequestMethod) != ""
}
