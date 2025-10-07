package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/middleware"
)

const OriginWildcard = "*"

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
		AllowedOrigins: []string{OriginWildcard},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodHead,
			http.MethodOptions,
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
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
	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != OriginWildcard {
		c.AllowedOrigins = make(map[string]struct{}, len(cfg.AllowedOrigins))
		for _, origin := range cfg.AllowedOrigins {
			c.AllowedOrigins[origin] = struct{}{}
		}
	}
	return c
}

func Middleware(cfg Config) middleware.Pipe {
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
			if c.AllowCredentials {
				h.Set(header.AccessControlAllowOrigin, origin)
			} else if c.AllowedOrigins == nil {
				h.Set(header.AccessControlAllowOrigin, OriginWildcard)
			} else {
				h.Set(header.AccessControlAllowOrigin, origin)
			}
			h.Add(header.Vary, header.Origin)
			if Preflight(r) {
				h.Set(header.AccessControlAllowMethods, c.AllowedMethods)
				if c.AllowedHeaders != "" {
					h.Set(header.AccessControlAllowHeaders, c.AllowedHeaders)
				}
				if c.AllowCredentials {
					h.Set(header.AccessControlAllowCredentials, "true")
				}
				if c.MaxAge != "" {
					h.Set(header.AccessControlMaxAge, c.MaxAge)
				}
				w.WriteHeader(http.StatusNoContent)
			} else {
				if c.ExposedHeaders != "" {
					h.Set(header.AccessControlExposeHeaders, c.ExposedHeaders)
				}
				if c.AllowCredentials {
					h.Set(header.AccessControlAllowCredentials, "true")
				}
				next.ServeHTTP(w, r)
			}
		})
	}
}

func Preflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get(header.AccessControlRequestMethod) != ""
}
