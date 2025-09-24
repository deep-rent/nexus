package header

import (
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

func ParseRetryAfter(
	h http.Header,
	clock func() time.Time,
) (time.Duration, bool) {
	s := h.Get(RetryAfter)
	if s == "" {
		return 0, false
	}
	if d, err := strconv.ParseUint(s, 10, 64); err == nil {
		return time.Duration(d) * time.Second, true
	}
	if t, err := http.ParseTime(s); err == nil {
		return max(0, t.Sub(clock())), true
	}
	return 0, false
}

func ParseExpires(
	h http.Header,
	clock func() time.Time,
) (time.Duration, bool) {
	s := h.Get(Expires)
	if s == "" {
		return 0, false
	}
	t, err := http.ParseTime(s)
	if err != nil {
		return 0, false
	}
	return t.Sub(clock()), true
}

func ParseCacheControlMaxAge(
	h http.Header,
) (time.Duration, bool) {
	s := h.Get(CacheControl)
	if s == "" {
		return 0, false
	}
	for directive := range strings.SplitSeq(s, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(directive), "=")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "max-age") {
			if d, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Duration(d) * time.Second, true
			}
		}
	}
	return 0, false
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
