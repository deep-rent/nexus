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

package jwt

import (
	"time"
)

// VerifierOption defines a functional option for configuring a [Verifier].
type VerifierOption func(*verifierConfig)

// verifierConfig holds the configuration options for a [Verifier].
type verifierConfig struct {
	issuers   []string         // Set of trusted issuers
	audiences []string         // Set of trusted audiences
	leeway    time.Duration    // Clock skew tolerance
	age       time.Duration    // Maximum allowed token age
	now       func() time.Time // Time source for temporal validation
}

// WithIssuers adds one or more trusted issuers to the verifier. If a token's
// "iss" claim is missing or does not match one of these, it will be rejected.
// This option can be used multiple times to append additional values. By
// default, no issuer validation is performed.
func WithIssuers(iss ...string) VerifierOption {
	return func(c *verifierConfig) {
		c.issuers = append(c.issuers, iss...)
	}
}

// WithAudiences adds one or more trusted audiences to the verifier. If the
// token's "aud" claim is missing or does not contain at least one of these
// values, it will be rejected. This option can be used multiple times to append
// additional values. By default, no audience validation is performed.
func WithAudiences(aud ...string) VerifierOption {
	return func(c *verifierConfig) {
		c.audiences = append(c.audiences, aud...)
	}
}

// WithLeeway sets a grace period to allow for clock skew in temporal
// validations of the "exp", "nbf", and "iat" claims. It is subtracted from or
// added to the current time as appropriate. The default is zero, meaning no
// leeway. Negative values will be ignored.
func WithLeeway(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		if d > 0 {
			c.leeway = d
		}
	}
}

// WithMaxAge sets the maximum age for tokens based on their "iat" claim.
// Tokens without an "iat" claim will no longer be accepted. The default is
// zero, meaning no age validation. Negative values will be ignored.
func WithMaxAge(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		if d > 0 {
			c.age = d
		}
	}
}

// WithClock sets the function used to retrieve the current time during
// validation. This is useful for deterministic testing or synchronizing with
// an external time source. The default is [time.Now].
func WithClock(now func() time.Time) VerifierOption {
	return func(c *verifierConfig) {
		if now != nil {
			c.now = now
		}
	}
}
