// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package header provides a collection of utility functions for parsing,
// interpreting, and manipulating HTTP headers.
//
// The package includes helpers for common header-related tasks, such as:
//   - Parsing comma-separated directives (e.g., "max-age=3600").
//   - Parsing wildcard-aware content negotiation headers with q-factors.
//   - Parsing RFC 5988 Link headers to extract relations for API pagination.
//   - Extracting credentials from an Authorization header.
//   - Calculating cache lifetime from Cache-Control and Expires headers.
//   - Determining throttle delays from Retry-After and X-Ratelimit-* headers.
//
// It also provides a convenient http.RoundTripper implementation for
// automatically attaching a static set of headers to all outgoing requests.
package header

import (
	"iter"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Directives parses a comma-separated header value into an iterator of
// key-value pairs.
//
// For example, parsing "no-cache, max-age=3600" would yield twice: first
// "no-cache", "" and then "max-age", "3600".
func Directives(s string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for kv := range strings.SplitSeq(s, ",") {
			k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
			k = strings.ToLower(strings.TrimSpace(k))
			if ok {
				v = strings.TrimSpace(v)
			}
			if !yield(k, v) {
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
		for k, v := range Directives(v) {
			switch k {
			case "no-cache", "no-store":
				return 0
			case "max-age":
				if d, err := strconv.ParseInt(v, 10, 64); err == nil {
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

// Credentials extracts the credentials from the Authorization header of an
// HTTP request for a specific authentication scheme (e.g., "Basic", "Bearer").
//
// It returns the raw credentials as-is, or an empty string if the header is
// not present, not well-formed, or does not match the specified scheme. The
// scheme comparison is case-insensitive.
func Credentials(h http.Header, scheme string) string {
	auth := h.Get("Authorization")
	if auth == "" {
		return ""
	}
	prefix, credentials, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(prefix, scheme) {
		return ""
	}
	return credentials
}

// Preferences parses a header value with quality factors (e.g., Accept,
// Accept-Encoding, Accept-Language) into an iterator quality factors (q-value)
// by name (media range). The values are yielded in the order they appear in the
// header, not sorted by quality. Values without an explicit q-factor are
// assigned a default quality of 1.0. Malformed q-factors are also treated as
// 1.0, while out-of-range values are clamped into the [0.0, 1.0] interval.
func Preferences(s string) iter.Seq2[string, float64] {
	return func(yield func(string, float64) bool) {
		for part := range strings.SplitSeq(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			params := strings.Split(part, ";")
			var q = 1.0
			for i := 1; i < len(params); i++ {
				p := strings.TrimSpace(params[i])
				k, v, found := strings.Cut(p, "=")
				if found && strings.TrimSpace(k) == "q" {
					v = strings.TrimSpace(v)
					if f, err := strconv.ParseFloat(v, 64); err == nil {
						q = min(1.0, max(0.0, f))
					}
					break
				}
			}
			if !yield(strings.TrimSpace(params[0]), q) {
				return
			}
		}
	}
}

// Accepts checks if the given key is accepted based on a header value with
// quality factors (e.g., Accept, Accept-Encoding, or Accept-Language).
// It properly weights exact matches over partial wildcards (e.g., "text/*")
// and global wildcards ("*/*" or "*"), returning true if the best match has
// a q-value greater than zero.
func Accepts(s, key string) bool {
	var (
		maxQ float64
		maxP int
	)

	// Extract the major type (e.g., "text" from "text/html") for partial
	// wildcards.
	major, _, hasSlash := strings.Cut(key, "/")

	for k, q := range Preferences(s) {
		var p int
		if k == key {
			p = 3 // Exact match (highest precedence)
		} else if hasSlash && k == major+"/*" {
			p = 2 // Partial wildcard match (e.g., "text/*")
		} else if k == "*/*" || k == "*" {
			p = 1 // Global wildcard match
		}

		// Update if we found a more specific match than our current best.
		if p > maxP {
			maxP = p
			maxQ = q
		}
	}

	// It is accepted if we found a valid match and its q-value is greater than 0.
	return maxP > 0 && maxQ > 0
}

// MediaType extracts and returns the media type from a Content-Type header.
// It returns the media type in lowercase, trimmed of whitespace. If the header
// is empty or malformed, it returns an empty string.
//
// This function is similar to mime.ParseMediaType but does not return any
// parameters and ignores parsing errors.
func MediaType(h http.Header) string {
	v := h.Get("Content-Type")
	if v == "" {
		return ""
	}
	i := strings.IndexByte(v, ';')
	if i != -1 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// Links parses an RFC 5988 Link header into an iterator of relation types (rel)
// and their corresponding URLs.
//
// If a link has multiple space-separated relations (e.g., rel="next archive"),
// it yields the URL for each relation separately.
func Links(s string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for part := range strings.SplitSeq(s, ",") {
			s := strings.IndexByte(part, '<')
			e := strings.IndexByte(part, '>')

			// Ensure the URL brackets are present and valid.
			if s == -1 || e == -1 || s >= e {
				continue
			}
			url := part[s+1 : e]

			// Parse the parameters following the URL.
			params := strings.SplitSeq(part[e+1:], ";")
			for p := range params {
				p = strings.TrimSpace(p)
				k, v, found := strings.Cut(p, "=")

				if found && strings.ToLower(strings.TrimSpace(k)) == "rel" {
					// Remove optional quotes around the relation value.
					v = strings.Trim(strings.TrimSpace(v), `"`)

					// A single link can have multiple relation types.
					for rel := range strings.FieldsSeq(v) {
						if !yield(strings.ToLower(rel), url) {
							return
						}
					}
				}
			}
		}
	}
}

// Link extracts the URL for a specific relation (e.g., "next" or "last") from
// a Link header. It returns an empty string if the relation is not found.
func Link(s, rel string) string {
	rel = strings.ToLower(rel)
	for k, v := range Links(s) {
		if k == rel {
			return v
		}
	}
	return ""
}

// Filename extracts the intended filename from a Content-Disposition header.
//
// It automatically handles both the standard "filename" parameter and the
// RFC 6266 "filename*" parameter, which is used for non-ASCII (UTF-8) names.
// It returns an empty string if the header is missing, malformed, or does
// not contain a filename.
func Filename(h http.Header) string {
	v := h.Get("Content-Disposition")
	if v == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(v)
	if err != nil {
		return ""
	}
	// The filename* parameter is decoded automatically.
	return params["filename"]
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

// UserAgent constructs a User-Agent header with the specified name, version,
// and an optional comment. The resulting value follows the format "name/version
// (comment)". The first part is the product token, while the parenthesized
// section provides supplementary information about the client. For external
// calls, it is best practice to include maintainer contact details in the
// comment (such as an URL or email address).
func UserAgent(name, version, comment string) Header {
	value := name + "/" + version
	if comment != "" {
		value += " (" + comment + ")"
	}
	return Header{
		Key:   "User-Agent",
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
		clone.Header.Set(h.Key, h.Value)
	}
	return t.wrapped.RoundTrip(clone)
}

var _ http.RoundTripper = (*transport)(nil)

// NewTransport wraps a base transport and sets a static set of headers on
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
