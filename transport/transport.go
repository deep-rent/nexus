package transport

import (
	"log/slog"
	"net/http"
	"time"
)

type headerTransport struct {
	wrapped http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	return t.wrapped.RoundTrip(clone)
}

var _ http.RoundTripper = (*headerTransport)(nil)

// WithHeaders wraps a base transport and sets a static set of headers on
// each outgoing request. If the base transport is nil, it falls back to
// http.DefaultTransport. If the provided headers map is empty, the base
// transport is returned unmodified. The function creates a defensive copy of
// the provided map. The resulting transport clones the request before
// delegating to the base transport, so the original request is not changed.
func WithHeaders(
	t http.RoundTripper,
	headers map[string]string,
) http.RoundTripper {
	if t == nil {
		t = http.DefaultTransport
	}
	if len(headers) == 0 {
		return t
	}
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[http.CanonicalHeaderKey(k)] = v
	}
	return &headerTransport{
		wrapped: t,
		headers: h,
	}
}

// WithHeader is a shorthand for WithHeaders with a single header.
func WithHeader(
	t http.RoundTripper,
	k, v string,
) http.RoundTripper {
	return WithHeaders(t, map[string]string{k: v})
}

type loggerTransport struct {
	wrapped http.RoundTripper
	log     *slog.Logger
}

func (t *loggerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	t.log.Info("Sending request", "method", req.Method, "url", req.URL)

	res, err := t.wrapped.RoundTrip(req)
	duration := time.Since(start)
	if err != nil {
		t.log.Error("Request failed", "error", err, "duration", duration)
		return nil, err
	}

	sc := res.StatusCode
	t.log.Info("Received response", "status", sc, "duration", duration)
	return res, nil
}

// WithLogger wraps a base transport and logs the start and end of each
// request, along with its duration. If the base transport is nil, it falls
// back to http.DefaultTransport. If the provided logger is nil, it falls back
// to slog.Default(). The resulting transport does not modify the request or
// response in any way.
func WithLogger(t http.RoundTripper, log *slog.Logger) http.RoundTripper {
	if t == nil {
		t = http.DefaultTransport
	}
	if log == nil {
		log = slog.Default()
	}
	return &loggerTransport{
		wrapped: t,
		log:     log,
	}
}
