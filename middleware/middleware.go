package middleware

import "net/http"

type Pipe func(http.Handler) http.Handler

func Link(h http.Handler, pipes ...Pipe) http.Handler {
	for i := len(pipes) - 1; i >= 0; i-- {
		h = pipes[i](h)
	}
	return h
}
