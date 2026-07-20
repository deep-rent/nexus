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
// It also provides a convenient [http.RoundTripper] implementation for
// automatically attaching a static set of headers to all outgoing requests.
package header

import (
	"iter"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/internal/ascii"
)

// Directives parses a comma-separated header value into an iterator of
// key-value pairs.
//
// For example, parsing "no-cache, max-age=3600" would yield twice: first
// "no-cache", "" and then "max-age", "3600".
//
// Keys are lowercased. Values are unquoted, and commas inside a quoted value
// do not split the header, so `no-cache="Set-Cookie", max-age=60` yields
// "no-cache", "Set-Cookie" followed by "max-age", "60".
func Directives(s string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for kv := range fields(s, ',') {
			k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
			k = ascii.ToLower(strings.TrimSpace(k))
			if ok {
				v = unquote(strings.TrimSpace(v))
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
//
// Directives are evaluated as a set rather than in the order they appear, so
// a no-store or no-cache anywhere in Cache-Control suppresses the lifetime
// even when a max-age precedes it. A no-cache that names specific fields
// (no-cache="Set-Cookie") only marks those fields for revalidation and leaves
// the lifetime intact.
//
// The time a response has already spent in upstream caches, as reported by
// the Age header, is subtracted from a max-age. No such correction applies to
// Expires, which names an absolute instant and is therefore measured against
// the clock directly.
func Lifetime(h http.Header, now func() time.Time) time.Duration {
	// Cache-Control takes precedence over Expires
	if v := h.Get("Cache-Control"); v != "" {
		var (
			maxAge time.Duration
			found  bool
		)

		for k, v := range Directives(v) {
			switch k {
			case "no-store":
				return 0
			case "no-cache":
				// Only the unqualified form forbids reuse outright.
				if v == "" {
					return 0
				}
			case "max-age":
				if d, err := strconv.ParseInt(v, 10, 64); err == nil {
					// A negative age denotes a response that is already
					// stale, not one that expired in the past.
					maxAge, found = max(0, time.Duration(d)*time.Second), true
				}
			}
		}

		if found {
			// What remains of the age budget after the time the response
			// already spent being relayed.
			return max(0, maxAge-Age(h))
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

// Age reports how long a response has been held in caches on its way to the
// client, as stated by the Age header. It returns 0 if the header is absent,
// malformed, or negative.
func Age(h http.Header) time.Duration {
	v := h.Get("Age")
	if v == "" {
		return 0
	}
	d, err := strconv.ParseInt(v, 10, 64)
	if err != nil || d < 0 {
		return 0
	}
	return time.Duration(d) * time.Second
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
		for part := range fields(s, ',') {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			params := slices.Collect(fields(part, ';'))
			q := 1.0
			for i := 1; i < len(params); i++ {
				p := strings.TrimSpace(params[i])
				k, v, found := strings.Cut(p, "=")
				if found && strings.TrimSpace(k) == "q" {
					v = unquote(strings.TrimSpace(v))
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
	major, _, has := strings.Cut(key, "/")

	for k, q := range Preferences(s) {
		var p int
		switch {
		case k == key:
			p = 3 // Exact match (highest precedence)
		case has && k == major+"/*":
			p = 2 // Partial wildcard match (e.g., "text/*")
		case k == "*/*" || k == "*":
			p = 1 // Global wildcard match
		}

		// Update if we found a more specific match than our current best.
		if p > maxP {
			maxP = p
			maxQ = q
		}
	}

	// It is accepted if we found a valid match and its q-value is greater than
	// 0.
	return maxP > 0 && maxQ > 0
}

// MediaType extracts and returns the media type from a Content-Type header.
// It returns the media type in lowercase, trimmed of whitespace. If the header
// is empty or malformed, it returns an empty string.
//
// This function is similar to [mime.ParseMediaType] but does not return any
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
	return ascii.ToLower(strings.TrimSpace(v))
}

// Links parses an RFC 5988 Link header into an iterator of relation types (rel)
// and their corresponding URLs.
//
// If a link has multiple space-separated relations (e.g., rel="next archive"),
// it yields the URL for each relation separately. Commas inside the angle
// brackets belong to the link target and do not separate links, which matters
// for URLs whose query string enumerates several values.
func Links(s string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for part := range fields(s, ',') {
			sidx := strings.IndexByte(part, '<')
			eidx := strings.IndexByte(part, '>')

			// Ensure the URL brackets are present and valid.
			if sidx == -1 || eidx == -1 || sidx >= eidx {
				continue
			}
			url := part[sidx+1 : eidx]

			// Parse the parameters following the URL.
			params := fields(part[eidx+1:], ';')
			for p := range params {
				p = strings.TrimSpace(p)
				k, v, found := strings.Cut(p, "=")

				if found && ascii.ToLower(strings.TrimSpace(k)) == "rel" {
					// Remove optional quotes around the relation value.
					v = unquote(strings.TrimSpace(v))

					// A single link can have multiple relation types.
					for rel := range strings.FieldsSeq(v) {
						if !yield(ascii.ToLower(rel), url) {
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
	rel = ascii.ToLower(rel)
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
//
// The value is chosen by whoever sent the response, so it is reduced to a bare
// base name: directory components are stripped, and names that would resolve
// to a directory or carry a null byte are rejected. Without this, a header
// such as `attachment; filename="../../etc/passwd"` would hand the caller a
// path that escapes the directory it is joined to. The result is still
// untrusted input and should not be used as a path without further checks.
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
	return basename(params["filename"])
}

// basename reduces a filename supplied by a remote party to its last path
// element, rejecting values that cannot name a file.
func basename(name string) string {
	// Both separators are stripped regardless of the host platform, since the
	// sender may report a Windows path to a server running elsewhere.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}

	name = strings.TrimSpace(name)
	if name == "." || name == ".." || strings.ContainsRune(name, 0) {
		return ""
	}
	return name
}

// Header represents a single HTTP header key-value pair.
type Header struct {
	// Key is the canonicalized header name.
	Key string
	// Value is the raw value of the header.
	Value string
}

// String formats the header as "Key: Value".
func (h Header) String() string {
	return h.Key + ": " + h.Value
}

// New creates a new [Header] with the given key and value. The key is
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

// transport is an internal [http.RoundTripper] that injects static headers.
type transport struct {
	// wrapped is the underlying RoundTripper.
	wrapped http.RoundTripper
	// headers are the static headers to be injected into each request.
	headers []Header
}

// RoundTrip clones the request and adds static headers before delegating.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for _, h := range t.headers {
		clone.Header.Set(h.Key, h.Value)
	}
	return t.wrapped.RoundTrip(clone)
}

var _ http.RoundTripper = (*transport)(nil)

// NewTransport wraps a base transport and sets a static set of headers on
// each outgoing request. If no headers are provided, the base transport is
// returned unmodified.
//
// The headers are copied, so later changes to the caller's slice do not affect
// the transport. The resulting transport also clones each request before
// delegating, so the original request is not changed either.
func NewTransport(
	t http.RoundTripper,
	headers ...Header,
) http.RoundTripper {
	if len(headers) == 0 {
		return t
	}
	return &transport{
		wrapped: t,
		// A variadic call site may pass a slice the caller keeps hold of.
		headers: slices.Clone(headers),
	}
}
