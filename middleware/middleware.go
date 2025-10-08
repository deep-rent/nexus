// Package middleware provides utilities for chaining and composing HTTP
// middleware handlers, besides some common middleware implementations like
// panic recovery and logging.
//
// # Usage
//
//	logger := slog.Default()
//	// Create the final handler.
//	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Write([]byte("OK"))
//	})
//	// Chain the middleware around the final handler.
//	h = middleware.Chain(h,
//		middleware.Recover(logger),
//		middleware.RequestID(),
//		middleware.Log(logger),
//	)
//	http.ListenAndServe(":8080", h)
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/deep-rent/nexus/header"
)

// Pipe defines the structure for a middleware function. It takes an
// http.Handler as input and returns a new http.Handler, allowing for the
// composition of middleware.
type Pipe func(http.Handler) http.Handler

// Chain combines multiple middleware Pipes into a single http.Handler. The
// pipes are applied in the order they are provided, with the first pipe
// becoming the outermost layer and the last pipe the innermost, directly
// wrapping the final handler.
func Chain(h http.Handler, pipes ...Pipe) http.Handler {
	for i := len(pipes) - 1; i >= 0; i-- {
		if pipe := pipes[i]; pipe != nil {
			h = pipe(h)
		}
	}
	return h
}

// Recover produces a middleware Pipe that catches panics in downstream
// handlers. It uses the provided logger to report the exception with a stack
// trace and returns an empty response with status code 500 to the client. The
// log entry also pinpoints the request method and URL that caused the panic.
func Recover(logger *slog.Logger) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					method, url := r.Method, r.URL.String()
					logger.Error(
						"Panic caught by middleware",
						"method", method,
						"url", url,
						"error", err,
						"stack", string(debug.Stack()),
					)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// Skipper is a function that returns true if the middleware should be skipped
// for the given request.
type Skipper func(r *http.Request) bool

// Skip returns a new middleware Pipe that conditionally skips the specified
// pipe if the condition is satisfied.
func Skip(pipe Pipe, condition Skipper) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if condition(r) {
				next.ServeHTTP(w, r)
				return
			}
			pipe(next).ServeHTTP(w, r)
		})
	}
}

type contextKey string // Prevents collisions with other packages.

const keyRequestID = contextKey("requestID")

// RequestID creates a middleware Pipe that generates a unique 128-bit ID for
// each request, adding it to the 'X-Request-ID' response header and the
// request's context.
func RequestID() Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				next.ServeHTTP(w, r)
				return
			}
			id := hex.EncodeToString(b)
			w.Header().Set(header.XRequestID, id)
			next.ServeHTTP(w, r.WithContext(SetRequestID(r.Context(), id)))
		})
	}
}

// GetRequestID retrieves the request ID from a given context. It returns an
// empty string if the ID is not found.
func GetRequestID(ctx context.Context) string {
	id, _ := ctx.Value(keyRequestID).(string)
	return id
}

// SetRequestID sets the request ID in the provided context, returning a new
// context that carries the ID.
func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// responseWriterInterceptor is used to wrap the original http.ResponseWriter to
// capture the status code.
type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before calling the original WriteHeader.
func (rwi *responseWriterInterceptor) WriteHeader(code int) {
	rwi.statusCode = code
	rwi.ResponseWriter.WriteHeader(code)
}

// Log creates a middleware Pipe that logs a summary of each HTTP request after
// it has been handled. The log entry is generated at the debug level and
// includes the request ID, method, URL, remote address, user agent, the final
// HTTP status code, and the total processing duration.
func Log(logger *slog.Logger) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rwi := &responseWriterInterceptor{w, http.StatusOK}
			next.ServeHTTP(rwi, r)
			logger.Debug(
				"HTTP request handled",
				slog.String("id", GetRequestID(r.Context())),
				slog.String("method", r.Method),
				slog.String("url", r.URL.String()),
				slog.String("remote", r.RemoteAddr),
				slog.String("agent", r.UserAgent()),
				slog.Int("status", rwi.statusCode),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}
