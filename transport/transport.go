package transport

import "net/http"

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	return t.base.RoundTrip(clone)
}

var _ http.RoundTripper = (*headerTransport)(nil)

// WithHeaders wraps a base transport and sets a static set of headers on
// each outgoing request. If the base transport is nil, it falls back to
// http.DefaultTransport. If the provided headers map is empty, the base
// transport is returned unmodified. The function creates a defensive copy of
// the provided map. The resulting transport clones the request before
// delegating to the base transport, so the original request is not changed.
func WithHeaders(
	base http.RoundTripper,
	headers map[string]string,
) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if len(headers) == 0 {
		return base
	}
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[http.CanonicalHeaderKey(k)] = v
	}
	return &headerTransport{
		base:    base,
		headers: h,
	}
}
