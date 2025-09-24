package header

import (
	"iter"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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

const (
	XFrameOptions          = "X-Frame-Options"
	XXSSProtection         = "X-XSS-Protection"
	ContentSecurityPolicy  = "Content-Security-Policy"
	XContentSecurityPolicy = "X-Content-Security-Policy"
	XWebKitCSP             = "X-WebKit-CSP"
	XContentTypeOptions    = "X-Content-Type-Options"
	XPoweredBy             = "X-Powered-By"
	XUACompatible          = "X-UA-Compatible"
	XForwardedProto        = "X-Forwarded-Proto"
	XHTTPMethodOverride    = "X-HTTP-Method-Override"
	XForwardedFor          = "X-Forwarded-For"
	XRealIP                = "X-Real-IP"
	XCSRFToken             = "X-CSRF-Token"
	XRatelimitLimit        = "X-Ratelimit-Limit"
	XRatelimitRemaining    = "X-Ratelimit-Remaining"
	XRatelimitReset        = "X-Ratelimit-Reset"
)

type Directive struct {
	Key   string
	Value string
}

func (d Directive) String() string {
	if d.Value == "" {
		return d.Key
	}
	return d.Key + "=" + d.Value
}

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

func Throttle(h http.Header, now func() time.Time) time.Duration {
	if v := h.Get(RetryAfter); v != "" {
		if d, err := strconv.ParseUint(v, 10, 64); err == nil {
			return time.Duration(d) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := t.Sub(now()); d > 0 {
				return d
			}
		}
	}
	return 0
}

func Lifetime(h http.Header, now func() time.Time) time.Duration {
	if v := h.Get(CacheControl); v != "" {
		for d := range Directives(v) {
			switch d.Key {
			case "no-cache", "no-store":
				return 0
			case "max-age":
				if s, err := strconv.ParseUint(d.Value, 10, 64); err == nil {
					return time.Duration(s) * time.Second
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
	return &headerTransport{
		wrapped: t,
		headers: h,
	}
}
