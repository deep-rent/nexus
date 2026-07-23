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

package cors

import (
	"net/http"

	"github.com/deep-rent/nexus/net/middleware"
)

// wildcard is a special value that can be passed in configuration to allow
// requests from any origin.
const wildcard = "*"


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
