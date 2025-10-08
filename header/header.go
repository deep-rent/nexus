// Package header provides a collection of utility functions for parsing,
// interpreting, and manipulating HTTP headers.
//
// The package includes helpers for common header-related tasks, such as:
//   - Parsing comma-separated directives (e.g., "max-age=3600").
//   - Parsing and sorting content negotiation headers with q-factors (e.g., Accept).
//   - Extracting credentials from an Authorization header.
//   - Calculating cache lifetime from Cache-Control and Expires headers.
//   - Determining throttle delays from Retry-After and X-Ratelimit-* headers.
//
// It also provides a convenient http.RoundTripper implementation for
// automatically adding a static set of headers to all outgoing requests.
package header

import (
	"iter"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Directive represents a single key-value pair from a header value,
// such as "max-age=3600" in a Cache-Control header.
type Directive struct {
	// Key is the directive's key, always converted to lower-case.
	Key string
	// Value is the directive's value. It is empty if the directive is a flag.
	Value string
}

// String formats the directive back into its standard string representation.
// If the value is empty, it returns only the key (e.g., "no-cache").
func (d Directive) String() string {
	if d.Value == "" {
		return d.Key
	}
	return d.Key + "=" + d.Value
}

// Directives parses a comma-separated header value into an iterator of
// Directive structs.
//
// For example, parsing "no-cache, max-age=3600" would yield two Directives:
// {Key: "no-cache", Value: ""} and {Key: "max-age", Value: "3600"}.
func Directives(value string) iter.Seq[Directive] {
	return func(yield func(Directive) bool) {
		for part := range strings.SplitSeq(value, ",") {
			k, v, found := strings.Cut(strings.TrimSpace(part), "=")
			k = strings.ToLower(strings.TrimSpace(k))
			if found {
				v = strings.TrimSpace(v)
			}
			if !yield(Directive{
				Key:   k,
				Value: v,
			}) {
				return
			}
		}
	}
}

// Throttle determines the required delay before the next request based on
// rate-limiting headers in the response. It accepts a clock function to
// calculate relative times. If no throttling is indicated, it returns a
// duration of 0.
func Throttle(h http.Header, now func() time.Time) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if d, err := strconv.ParseInt(v, 10, 64); err == nil && d > 0 {
			return time.Duration(d) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := t.Sub(now()); d > 0 {
				return d
			}
		}
	}
	if h.Get("X-Ratelimit-Remaining") == "0" {
		if v := h.Get("X-Ratelimit-Reset"); v != "" {
			if t, err := strconv.ParseInt(v, 10, 64); err == nil && t > 0 {
				if d := time.Unix(t, 0).Sub(now()); d > 0 {
					return d
				}
			}
		}
	}
	return 0
}

// Lifetime determines the cache lifetime of a response based on caching
// headers. It accepts a clock function to calculate relative times. It returns
// a duration of 0 if the response is not cacheable or does not carry any
// caching information.
func Lifetime(h http.Header, now func() time.Time) time.Duration {
	// Cache-Control takes precedence over Expires
	if v := h.Get("Cache-Control"); v != "" {
		for kv := range Directives(v) {
			switch kv.Key {
			case "no-cache", "no-store":
				return 0
			case "max-age":
				if d, err := strconv.ParseInt(kv.Value, 10, 64); err == nil {
					return time.Duration(d) * time.Second
				}
			}
		}
	}
	if v := h.Get("Expires"); v != "" {
		if t, err := http.ParseTime(v); err == nil {
			if d := t.Sub(now()); d > 0 {
				return d
			}
		}
	}
	return 0
}

// Credentials extracts the authentication scheme and credentials from the
// Authorization header of an HTTP request. It returns the scheme in lower-case
// (e.g., "basic", "bearer"), the credentials as-is, and a boolean indicating
// whether the header was present and well-formed.
func Credentials(r *http.Request) (scheme string, credentials string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return
	}
	scheme = strings.ToLower(parts[0])
	credentials = parts[1]
	ok = true
	return
}

// Preference represents a single preference from an Accept-* style header,
// combining a value with its quality factor (q-value).
type Preference struct {
	// Value is the raw value of the preference, e.g., "application/json".
	Value string
	// Q is the quality factor, ranging from 0.0 to 1.0. If not specified in
	// the header, it defaults to 1.0.
	Q float64
}

// Preferences parses a header value with quality factors (e.g., Accept,
// Accept-Language) into an slice of Preference structs. The returned slice is
// sorted in descending order of quality factor (from highest to lowest
// preference). Values without an explicit q-factor are assigned a default
// quality of 1.0. Malformed q-factors are also treated as 1.0.
//
// Example:
//
//	Input: "text/html, application/json;q=0.9, */*;q=0.8"
//	Output:
//	  []Preference{
//	    {Value: "text/html", Q: 1.0},
//	    {Value: "application/json", Q: 0.9},
//	    {Value: "*/*", Q: 0.8},
//	  }
func Preferences(value string) []Preference {
	var prefs []Preference
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		params := strings.Split(part, ";")
		spec := Preference{
			Value: strings.TrimSpace(params[0]),
			Q:     1.0,
		}
		for i := 1; i < len(params); i++ {
			p := strings.TrimSpace(params[i])
			k, v, found := strings.Cut(p, "=")
			if found && strings.TrimSpace(k) == "q" {
				if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					spec.Q = q
				}
				break
			}
		}
		prefs = append(prefs, spec)
	}
	sort.SliceStable(prefs, func(i, j int) bool {
		return prefs[i].Q > prefs[j].Q
	})
	return prefs
}

// Header represents a single HTTP header key-value pair.
type Header struct {
	Key   string // Key is the canonicalized header name.
	Value string // Value is the raw value of the header.
}

// String formats the header as "Key: Value".
func (h Header) String() string {
	return h.Key + ": " + h.Value
}

// New creates a new Header with the given key and value. The key is
// automatically canonicalized to the standard HTTP header format.
func New(key, value string) Header {
	return Header{
		Key:   http.CanonicalHeaderKey(key),
		Value: value,
	}
}

type transport struct {
	wrapped http.RoundTripper
	headers []Header
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for _, h := range t.headers {
		clone.Header.Add(h.Key, h.Value)
	}
	return t.wrapped.RoundTrip(clone)
}

var _ http.RoundTripper = (*transport)(nil)

// NewTransport wraps a base transport and adds a static set of headers on
// each outgoing request. If the provided headers map is empty, the base
// transport is returned unmodified. The function creates a defensive copy of
// the provided map. The resulting transport clones the request before
// delegating to the base transport, so the original request is not changed.
func NewTransport(
	t http.RoundTripper,
	headers ...Header,
) http.RoundTripper {
	if len(headers) == 0 {
		return t
	}
	return &transport{
		wrapped: t,
		headers: headers,
	}
}
