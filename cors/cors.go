package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/middleware"
)

const Wildcard = "*"
const DefaultAllowCredentials = true
const DefaultMaxAge = 12 * time.Hour

type Config struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

func DefaultConfig() Config {
	return Config{
		AllowedOrigins: []string{Wildcard},
		AllowedMethods: []string{
			http.MethodDelete,
			http.MethodGet,
			http.MethodHead,
			http.MethodOptions,
			http.MethodPatch,
			http.MethodPost,
			http.MethodPut,
		},
		AllowCredentials: DefaultAllowCredentials,
		MaxAge:           DefaultMaxAge,
	}
}

type config struct {
	AllowedOrigins   map[string]struct{}
	AllowedMethods   string
	AllowedHeaders   string
	ExposedHeaders   string
	AllowCredentials bool
	MaxAge           string
}

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
	if len(cfg.AllowedOrigins) > 1 || cfg.AllowedOrigins[0] != Wildcard {
		c.AllowedOrigins = make(map[string]struct{}, len(cfg.AllowedOrigins))
		for _, origin := range cfg.AllowedOrigins {
			c.AllowedOrigins[origin] = struct{}{}
		}
	}
	return c
}

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
