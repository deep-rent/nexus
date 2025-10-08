// Package middleware provides a standard approach for chaining and composing
// HTTP middleware.
//
// # Usage
//
// The core type is Pipe, an adapter that wraps an http.Handler to add
// functionality. The Chain function composes these pipes into a single handler.
// The package also includes common middleware like Recover for panic handling,
// RequestID for tracing, and Log for request logging.
//
// Example:
//
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Write([]byte("OK"))
//	})
//
//	// Chain middleware around the final handler.
//	// Order matters: Recover must be first (outermost).
//	logger := slog.Default()
//	chainedHandler := middleware.Chain(handler,
//		middleware.Recover(logger),
//		middleware.RequestID(),
//		middleware.Log(logger),
//	)
//
//	http.ListenAndServe(":8080", chainedHandler)
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// Pipe is a middleware function. It's an adapter that takes an http.Handler
// and returns a new http.Handler, allowing functionality to be composed in
// layers.
type Pipe func(http.Handler) http.Handler

// Chain combines a handler with multiple middleware Pipes. The pipes are
// applied in reverse order, meaning the first pipe in the list is the outermost
// and executes first.
//
// For example, Chain(h, A, B, C) results in a handler equivalent to A(B(C(h))).
// Any nil pipes in the list are safely ignored.
func Chain(h http.Handler, pipes ...Pipe) http.Handler {
	for i := len(pipes) - 1; i >= 0; i-- {
		if pipe := pipes[i]; pipe != nil {
			h = pipe(h)
		}
	}
	return h
}

// Skipper is a function that returns true if the middleware should be skipped
// for the given request.
type Skipper func(r *http.Request) bool

// Skip returns a new middleware Pipe that conditionally skips the specified
// pipe if the condition is satisfied. This is useful for excluding certain
// routes, like health probes, from middleware processing.
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

// Recover produces a middleware Pipe that catches panics in downstream
// handlers. It uses the provided logger to report the exception with a stack
// trace and returns an empty response with status code 500 to the client. The
// log entry also pinpoints the request method and URL that caused the panic.
// For maximum effectiveness, this should be the first (outermost) middleware
// in the chain.
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

type contextKey string // Prevents collisions with other packages.

// keyRequestID is the key under which the request ID is stored in the request
// context.
const keyRequestID = contextKey("RequestID")

// RequestID returns a middleware Pipe that injects a unique ID into each
// request. It adds the ID to the response via the "X-Request-ID" header and to
// the request's context for downstream use.
//
// Downstream handlers and other middleware can retrieve the ID using
// GetRequestID. If a unique ID cannot be generated from the random source, this
// middleware does nothing and passes the request to the next handler.
func RequestID() Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				next.ServeHTTP(w, r)
				return
			}
			id := hex.EncodeToString(b)
			w.Header().Set("X-Request-ID", id)
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

// interceptor is used to wrap the original http.ResponseWriter to
// capture the status code.
type interceptor struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before calling the original WriteHeader.
func (i *interceptor) WriteHeader(code int) {
	i.statusCode = code
	i.ResponseWriter.WriteHeader(code)
}

// Log returns a middleware Pipe that logs a summary of each HTTP request. It
// captures the final HTTP status code by wrapping the http.ResponseWriter.
//
// The log entry is generated at the debug level after the request has been
// handled. It includes the method, URL, status code, duration, and other
// common attributes. To include a request ID in the log, this middleware should
// be placed after the RequestID middleware in the chain.
func Log(logger *slog.Logger) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			incpt := &interceptor{w, http.StatusOK}
			next.ServeHTTP(incpt, r)
			logger.Debug(
				"HTTP request handled",
				slog.String("id", GetRequestID(r.Context())),
				slog.String("method", r.Method),
				slog.String("url", r.URL.String()),
				slog.String("remote", r.RemoteAddr),
				slog.String("agent", r.UserAgent()),
				slog.Int("status", incpt.statusCode),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}
