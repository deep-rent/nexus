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

package oauth

import (
	"net/http"

	"github.com/deep-rent/nexus/router"
)

// Key namespaces keep the identifier spaces disjoint, so that a client ID
// can never share a bucket with a username or a one-time code. Addresses are
// namespaced by the throttle package itself.
const (
	scopeClient = "client:"
	scopeUser   = "user:"
	scopeCode   = "code:"
)

// tooManyAttempts builds the OAuth-shaped rejection returned once a
// credential-verifying endpoint has exhausted its throttle allowance.
//
// RFC 6749 defines no error code for rate limiting, so the device-flow
// "slow_down" code (RFC 8628 Section 3.5) is reused: its semantics match
// exactly, and clients that do not recognize it still honor the 429 status
// and the accompanying Retry-After header.
func tooManyAttempts() *Error {
	return &Error{
		Status:      http.StatusTooManyRequests,
		Code:        ErrorCodeSlowDown,
		Description: "too many failed attempts",
	}
}

// tooManyRequests is the [router.Error] counterpart of [tooManyAttempts],
// used by the first-party JSON endpoints.
func tooManyRequests() *router.Error {
	return &router.Error{
		Status:      http.StatusTooManyRequests,
		Reason:      router.ReasonRateLimit,
		Description: "Too many failed attempts. Try again later.",
	}
}
