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

package header

import (
	"net/http"
	"slices"
)

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
