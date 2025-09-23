package middleware

import "net/http"

type Pipe func(http.Handler) http.Handler
