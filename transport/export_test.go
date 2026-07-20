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

package transport

import "net/http"

// Unwrap exposes the response body limiter to the external test package so
// that tests can inspect the limit and reach the transport underneath it. It
// reports whether rt is a limiter at all.
//
// This file is only compiled for tests, so none of it reaches the public API.
func Unwrap(rt http.RoundTripper) (http.RoundTripper, int64, bool) {
	lt, ok := rt.(*limitTransport)
	if !ok {
		return nil, 0, false
	}
	return lt.next, lt.max, true
}
