package header

import (
	"iter"
	"net/http"
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
	if v := h.Get(RetryAfter); v != "" {
		if d, err := strconv.ParseInt(v, 10, 64); err == nil && d > 0 {
			return time.Duration(d) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := t.Sub(now()); d > 0 {
				return d
			}
		}
	}
	if h.Get(XRatelimitRemaining) == "0" {
		if v := h.Get(XRatelimitReset); v != "" {
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
	if v := h.Get(CacheControl); v != "" {
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
	if v := h.Get(Expires); v != "" {
		if t, err := http.ParseTime(v); err == nil {
			if d := t.Sub(now()); d > 0 {
				return d
			}
		}
	}
	return 0
}

// Credentials extracts the authentication scheme and credentials from the
// Authorization header of an HTTP request. It returns the scheme in lower-case,
// the credentials as-is, and a boolean indicating whether the header was
// present and well-formed.
func Credentials(r *http.Request) (scheme string, credentials string, ok bool) {
	auth := r.Header.Get(Authorization)
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

type transport struct {
	wrapped http.RoundTripper
	headers map[string]string
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	return t.wrapped.RoundTrip(clone)
}

var _ http.RoundTripper = (*transport)(nil)

// NewTransport wraps a base transport and sets a static set of headers on
// each outgoing request. If the base transport is nil, it falls back to
// http.DefaultTransport. If the provided headers map is empty, the base
// transport is returned unmodified. The function creates a defensive copy of
// the provided map. The resulting transport clones the request before
// delegating to the base transport, so the original request is not changed.
func NewTransport(
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
	return &transport{
		wrapped: t,
		headers: h,
	}
}

// Standard HTTP headers
const (
	Accept                        = "Accept"
	AcceptCharset                 = "Accept-Charset"
	AcceptDatetime                = "Accept-Datetime"
	AcceptEncoding                = "Accept-Encoding"
	AcceptLanguage                = "Accept-Language"
	AcceptPatch                   = "Accept-Patch"
	AcceptRanges                  = "Accept-Ranges"
	AccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	AccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	AccessControlAllowMethods     = "Access-Control-Allow-Methods"
	AccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	AccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	AccessControlMaxAge           = "Access-Control-Max-Age"
	AccessControlRequestHeaders   = "Access-Control-Request-Headers"
	AccessControlRequestMethod    = "Access-Control-Request-Method"
	Allow                         = "Allow"
	Authorization                 = "Authorization"
	CacheControl                  = "Cache-Control"
	ContentDisposition            = "Content-Disposition"
	ContentEncoding               = "Content-Encoding"
	ContentLanguage               = "Content-Language"
	ContentLength                 = "Content-Length"
	ContentLocation               = "Content-Location"
	ContentMD5                    = "Content-MD5"
	ContentRange                  = "Content-Range"
	ContentSecurityPolicy         = "Content-Security-Policy"
	ContentType                   = "Content-Type"
	Cookie                        = "Cookie"
	DoNotTrack                    = "DNT"
	ETag                          = "ETag"
	Expires                       = "Expires"
	IfMatch                       = "If-Match"
	IfModifiedSince               = "If-Modified-Since"
	IfNoneMatch                   = "If-None-Match"
	IfRange                       = "If-Range"
	IfUnmodifiedSince             = "If-Unmodified-Since"
	LastModified                  = "Last-Modified"
	Link                          = "Link"
	Location                      = "Location"
	MaxForwards                   = "Max-Forwards"
	Origin                        = "Origin"
	P3P                           = "P3P"
	Pragma                        = "Pragma"
	ProxyAuthenticate             = "Proxy-Authenticate"
	ProxyAuthorization            = "Proxy-Authorization"
	Range                         = "Range"
	Referer                       = "Referer"
	Refresh                       = "Refresh"
	RetryAfter                    = "Retry-After"
	Server                        = "Server"
	SetCookie                     = "Set-Cookie"
	StrictTransportSecurity       = "Strict-Transport-Security"
	TE                            = "TE"
	TransferEncoding              = "Transfer-Encoding"
	Upgrade                       = "Upgrade"
	UserAgent                     = "User-Agent"
	Vary                          = "Vary"
	Via                           = "Via"
	Warning                       = "Warning"
	WWWAuthenticate               = "WWW-Authenticate"
)

// Non-standard HTTP headers
const (
	XContentSecurityPolicy = "X-Content-Security-Policy"
	XContentTypeOptions    = "X-Content-Type-Options"
	XCSRFToken             = "X-CSRF-Token"
	XForwardedFor          = "X-Forwarded-For"
	XForwardedProto        = "X-Forwarded-Proto"
	XFrameOptions          = "X-Frame-Options"
	XHTTPMethodOverride    = "X-HTTP-Method-Override"
	XPoweredBy             = "X-Powered-By"
	XRatelimitLimit        = "X-Ratelimit-Limit"
	XRatelimitRemaining    = "X-Ratelimit-Remaining"
	XRatelimitReset        = "X-Ratelimit-Reset"
	XRealIP                = "X-Real-IP"
	XRequestID             = "X-Request-ID"
	XUACompatible          = "X-UA-Compatible"
	XWebKitCSP             = "X-WebKit-CSP"
	XXSSProtection         = "X-XSS-Protection"
)

// Standard authentication schemes
const (
	SchemeBasic  = "basic"
	SchemeBearer = "bearer"
	SchemeDigest = "digest"
)
