// Package middleware provides utilities for chaining and composing HTTP
// middleware handlers.
package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
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
