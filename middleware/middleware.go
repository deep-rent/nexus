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

package middleware

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Pipe is a middleware function.
//
// Pipe is an adapter that takes an [http.Handler] and returns a new
// [http.Handler], allowing functionality to be composed in layers.
type Pipe func(http.Handler) http.Handler

// Chain combines a handler with multiple middleware Pipes.
//
// The pipes are applied in reverse order, meaning the first pipe in the list is
// the outermost and executes first. For example, Chain(h, A, B, C) results in a
// handler equivalent to A(B(C(h))). Any nil pipes in the list are safely
// ignored.
func Chain(h http.Handler, pipes ...Pipe) http.Handler {
	for _, pipe := range slices.Backward(pipes) {
		if pipe != nil {
			h = pipe(h)
		}
	}
	return h
}

// Passthrough is a no-op [Pipe] that returns the next handler unchanged.
//
// A no-op factory signals "no middleware" by returning nil, which [Chain] (and
// the router's Adapt) skip. Passthrough is instead a directly-callable
// identity, for callers that build a chain conditionally or need a safe pipe to
// invoke without a nil check.
func Passthrough(next http.Handler) http.Handler { return next }

// Recover produces a middleware [Pipe] that catches panics in downstream
// handlers.
//
// It uses the provided logger to report the exception with a stack trace and
// returns an empty response with status code 500 to the client. The log entry
// also pinpoints the request method and URL that caused the panic. For maximum
// effectiveness, this should be the first (outermost) middleware in the chain.
//
// Panics with [http.ErrAbortHandler] are re-raised untouched: the standard
// library uses this sentinel to abort a response on purpose, and the server
// suppresses its stack trace.
func Recover(logger *slog.Logger) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				defer func() {
					if r := recover(); r != nil {
						if err, ok := r.(error); ok &&
							errors.Is(err, http.ErrAbortHandler) {
							panic(r)
						}
						method, url := req.Method, req.URL.String()
						logger.Error(
							"Panic caught by middleware",
							slog.String("method", method),
							slog.String("url", url),
							slog.Any("panic", r),
							slog.String("stack", string(debug.Stack())),
						)
						res.WriteHeader(http.StatusInternalServerError)
					}
				}()

				next.ServeHTTP(res, req)
			},
		)
	}
}

// contextKey prevents collisions with other packages.
type contextKey struct{}

// requestIDKey is the key under which the request ID is stored in the request
// context.
var requestIDKey contextKey

// DefaultRequestIDHeader is the header used to transport the request ID
// unless overridden via [WithRequestIDHeader].
const DefaultRequestIDHeader = "X-Request-ID"

// requestIDConfig holds the configuration for the [RequestID] middleware.
type requestIDConfig struct {
	// header is the name of the request and response ID header.
	header string
	// trustClient reuses an inbound ID instead of generating a fresh one.
	trustClient bool
}

// RequestIDOption configures the [RequestID] middleware.
type RequestIDOption func(*requestIDConfig)

// WithRequestIDHeader overrides the header used to transport the request ID.
//
// Empty string values are ignored, keeping [DefaultRequestIDHeader].
func WithRequestIDHeader(name string) RequestIDOption {
	return func(c *requestIDConfig) {
		if name != "" {
			c.header = name
		}
	}
}

// WithTrustClient reuses a request ID supplied by the client.
//
// When enabled and the inbound request carries a syntactically valid ID in
// the configured header, that ID is propagated instead of generating a new
// one. This allows traces to span multiple services behind a gateway that
// assigns IDs. Only enable this behind infrastructure you control: the value
// is attacker-supplied otherwise, so IDs are capped at 64 characters and
// restricted to ASCII letters, digits, and "+-=/._" before being trusted.
func WithTrustClient(trust bool) RequestIDOption {
	return func(c *requestIDConfig) {
		c.trustClient = trust
	}
}

// validRequestID reports whether an inbound ID is safe to propagate.
func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case strings.IndexByte("+-=/._", c) != -1:
		default:
			return false
		}
	}
	return true
}

// RequestID returns a middleware [Pipe] that injects a unique ID into each
// request.
//
// It adds the ID to the response via the "X-Request-ID" header (configurable
// through [WithRequestIDHeader]) and to the request's context for downstream
// use. Downstream handlers and other middleware can retrieve the ID using
// [GetRequestID]. By default a fresh random ID is generated for every
// request; see [WithTrustClient] for propagating gateway-assigned IDs.
func RequestID(opts ...RequestIDOption) Pipe {
	cfg := requestIDConfig{header: DefaultRequestIDHeader}
	for _, opt := range opts {
		opt(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := ""
			if cfg.trustClient {
				if v := r.Header.Get(cfg.header); validRequestID(v) {
					id = v
				}
			}
			if id == "" {
				// Note: crypto/rand.Read is guaranteed not to fail.
				b := make([]byte, 16)
				_, _ = rand.Read(b)
				id = hex.EncodeToString(b)
			}
			w.Header().Set(cfg.header, id)
			next.ServeHTTP(w, r.WithContext(SetRequestID(r.Context(), id)))
		})
	}
}

// GetRequestID retrieves the request ID from a given context.
//
// It returns an empty string if the ID is not found.
func GetRequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// SetRequestID sets the request ID in the provided context.
//
// It returns a new context that carries the ID.
func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// interceptor is used to wrap the original [http.ResponseWriter] to capture
// the status code.
//
// It forwards the optional [http.Flusher] and [http.Hijacker] interfaces so
// that wrapping a handler does not disable streaming responses or protocol
// upgrades further down the chain.
type interceptor struct {
	// ResponseWriter is the original writer.
	http.ResponseWriter
	// statusCode is the captured HTTP response code.
	statusCode int
	// bytes is the number of body bytes written so far.
	bytes int64
}

// WriteHeader captures the status code before calling the original WriteHeader.
func (i *interceptor) WriteHeader(code int) {
	i.statusCode = code
	i.ResponseWriter.WriteHeader(code)
}

// Write counts the written bytes before delegating to the original Write.
func (i *interceptor) Write(b []byte) (int, error) {
	n, err := i.ResponseWriter.Write(b)
	i.bytes += int64(n)
	return n, err
}

// Flush implements [http.Flusher] by delegating to the underlying writer.
func (i *interceptor) Flush() {
	if flusher, ok := i.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap exposes the underlying writer, so that
// [http.NewResponseController] can reach optional interfaces implemented by
// it.
func (i *interceptor) Unwrap() http.ResponseWriter {
	return i.ResponseWriter
}

// Hijack implements [http.Hijacker] by delegating to the underlying writer.
func (i *interceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := i.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errors.New("hijacking not supported")
}

// Ensure interceptor implements the necessary contracts.
var (
	_ http.ResponseWriter = (*interceptor)(nil)
	_ http.Flusher        = (*interceptor)(nil)
	_ http.Hijacker       = (*interceptor)(nil)
)

// Log returns a middleware [Pipe] that logs a summary of each HTTP request.
//
// It captures the final HTTP status code and response size by wrapping the
// [http.ResponseWriter]. The log entry is generated at the debug level after
// the request has been handled. It includes the method, URL, status code,
// response size, duration, and other common attributes. To include a request
// ID in the log, this middleware should be placed after the [RequestID]
// middleware in the chain.
//
// If the logger has the debug level disabled, Log returns nil, which [Chain]
// (and the router's Adapt) skip entirely, so a disabled logger adds no chaining
// or per-request overhead. Enablement is decided once, when the pipe is built,
// so
// a logger whose level is raised to debug at runtime (e.g. via a
// [slog.LevelVar]) will not begin logging; rebuild the chain to pick that up.
func Log(logger *slog.Logger) Pipe {
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			incpt := &interceptor{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(incpt, r)
			logger.DebugContext(
				r.Context(),
				"HTTP request handled",
				slog.String("id", GetRequestID(r.Context())),
				slog.String("method", r.Method),
				slog.String("url", r.URL.String()),
				slog.String("remote", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.Int("status", incpt.statusCode),
				slog.Int64("bytes", incpt.bytes),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

// Volatile returns a middleware [Pipe] that prevents caching of the response.
//
// It sets standard HTTP headers (Cache-Control, Pragma, Expires) to ensure
// clients and proxies always fetch a fresh copy of the resource.
func Volatile() Pipe {
	control := strings.Join([]string{
		"no-store",
		"no-cache",
		"must-revalidate",
		"proxy-revalidate",
	}, ", ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", control)
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityConfig defines the headers applied by the [Secure] middleware.
type SecurityConfig struct {
	// STSMaxAge is the maximum age for HSTS in seconds. If 0, the header is
	// not set.
	STSMaxAge int64
	// STSIncludeSubdomains adds the "includeSubDomains" directive to HSTS.
	STSIncludeSubdomains bool
	// STSPreload adds the "preload" directive to HSTS, signaling consent to
	// inclusion in browser preload lists. Only set this if the site meets the
	// requirements of https://hstspreload.org (long max-age, subdomains
	// included), since removal from the lists is slow.
	STSPreload bool
	// FrameOptions sets the X-Frame-Options header (e.g., "DENY",
	// "SAMEORIGIN"). If empty, the header is not set.
	FrameOptions string
	// NoSniff sets X-Content-Type-Options to "nosniff" if true. This helps
	// prevent MIME type sniffing by browsers.
	NoSniff bool
	// CSP sets the Content-Security-Policy header. If empty, it is not set.
	CSP string
	// ReferrerPolicy sets the Referrer-Policy header. If empty, it is not set.
	ReferrerPolicy string
	// PermissionsPolicy sets the Permissions-Policy header. Example:
	// "geolocation=(), microphone=()"
	PermissionsPolicy string
	// CrossOriginOpenerPolicy sets the Cross-Origin-Opener-Policy header.
	// Recommended: "same-origin"
	CrossOriginOpenerPolicy string
	// CrossOriginEmbedderPolicy sets the Cross-Origin-Embedder-Policy header.
	CrossOriginEmbedderPolicy string
	// CrossOriginResourcePolicy sets the Cross-Origin-Resource-Policy header.
	CrossOriginResourcePolicy string
	// PermittedCrossDomainPolicies sets the X-Permitted-Cross-Domain-Policies
	// header, which restricts Adobe cross-domain policy files. Recommended:
	// "none". If empty, the header is not set.
	PermittedCrossDomainPolicies string
}

// DefaultSecurityConfig provides a baseline configuration.
//
// It enables HSTS for 1 year, disables MIME sniffing, protects against
// clickjacking by denying framing, suppresses the Referer header, and locks
// down cross-origin isolation and Adobe cross-domain policies.
var DefaultSecurityConfig = SecurityConfig{
	STSMaxAge:                    31536000,
	STSIncludeSubdomains:         true,
	FrameOptions:                 "DENY",
	NoSniff:                      true,
	ReferrerPolicy:               "no-referrer",
	PermissionsPolicy:            "geolocation=(),microphone=(),camera=(),payment=()",
	CrossOriginOpenerPolicy:      "same-origin",
	CrossOriginResourcePolicy:    "same-origin",
	PermittedCrossDomainPolicies: "none",
}

// Secure returns a middleware [Pipe] that sets security-related HTTP headers.
//
// Headers are set based on the provided configuration.
func Secure(cfg SecurityConfig) Pipe {
	// Pre-calculate HSTS header to avoid string allocation on every request.
	hsts := ""
	if cfg.STSMaxAge > 0 {
		hsts = "max-age=" + strconv.FormatInt(cfg.STSMaxAge, 10)
		if cfg.STSIncludeSubdomains {
			hsts += "; includeSubDomains"
		}
		if cfg.STSPreload {
			hsts += "; preload"
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// 1. Strict-Transport-Security
			if hsts != "" {
				h.Set("Strict-Transport-Security", hsts)
			}

			// 2. X-Content-Type-Options
			if cfg.NoSniff {
				h.Set("X-Content-Type-Options", "nosniff")
			}

			// 3. X-Frame-Options
			if cfg.FrameOptions != "" {
				h.Set("X-Frame-Options", cfg.FrameOptions)
			}

			// 4. Content-Security-Policy
			if cfg.CSP != "" {
				h.Set("Content-Security-Policy", cfg.CSP)
			}

			// 5. Referrer-Policy
			if cfg.ReferrerPolicy != "" {
				h.Set("Referrer-Policy", cfg.ReferrerPolicy)
			}

			// 6. Permissions-Policy
			if cfg.PermissionsPolicy != "" {
				h.Set("Permissions-Policy", cfg.PermissionsPolicy)
			}

			// 7. Cross-Origin-Opener-Policy
			if cfg.CrossOriginOpenerPolicy != "" {
				h.Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
			}

			// 8. Cross-Origin-Embedder-Policy
			if cfg.CrossOriginEmbedderPolicy != "" {
				h.Set(
					"Cross-Origin-Embedder-Policy",
					cfg.CrossOriginEmbedderPolicy,
				)
			}

			// 9. Cross-Origin-Resource-Policy
			if cfg.CrossOriginResourcePolicy != "" {
				h.Set(
					"Cross-Origin-Resource-Policy",
					cfg.CrossOriginResourcePolicy,
				)
			}

			// 10. X-Permitted-Cross-Domain-Policies
			if cfg.PermittedCrossDomainPolicies != "" {
				h.Set(
					"X-Permitted-Cross-Domain-Policies",
					cfg.PermittedCrossDomainPolicies,
				)
			}

			next.ServeHTTP(w, r)
		})
	}
}
