package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

type Pipe func(http.Handler) http.Handler

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
