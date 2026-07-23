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

package otp

import (
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
)

// Default policy values applied by [New] when the corresponding option is not
// given. They match the historical oauth two-factor defaults.
const (
	// DefaultLifetime is the validity period of a challenge.
	DefaultLifetime = 5 * time.Minute
	// DefaultMaxAttempts is the number of failed confirmations after which a
	// challenge is burned.
	DefaultMaxAttempts = 5
	// DefaultMaxResends is the number of times a single challenge may have its
	// code redelivered. A negative value disables resending entirely.
	DefaultMaxResends = 3
)

// Option configures a [Challenger].
type Option func(*Challenger)

// WithCodeSampler overrides the source of one-time passwords. A nil sampler
// is ignored. The default samples [DefaultLength] digits from [Digits]; build
// a custom sampler with [nonce.NewSampler] to change the length or alphabet.
func WithCodeSampler(s *nonce.Sampler) Option {
	return func(c *Challenger) {
		if s != nil {
			c.codes = s
		}
	}
}

// WithHasher sets the hasher that fingerprints handles and codes before they
// reach the store. A nil hasher is ignored. Defaults to
// [digest.DefaultHasher].
func WithHasher(h *digest.Hasher) Option {
	return func(c *Challenger) {
		if h != nil {
			c.hasher = h
		}
	}
}

// WithLifetime sets the validity period of a challenge. Nonpositive values are
// ignored. Defaults to [DefaultLifetime].
func WithLifetime(d time.Duration) Option {
	return func(c *Challenger) {
		if d > 0 {
			c.lifetime = d
		}
	}
}

// WithMaxAttempts sets the number of failed confirmations after which a
// challenge is burned. Values below 1 are ignored. Defaults to
// [DefaultMaxAttempts].
func WithMaxAttempts(n int) Option {
	return func(c *Challenger) {
		if n > 0 {
			c.maxAttempts = n
		}
	}
}

// WithMaxResends sets how many times a challenge's code may be redelivered. A
// negative value disables resending. Defaults to [DefaultMaxResends].
func WithMaxResends(n int) Option {
	return func(c *Challenger) { c.maxResends = n }
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [clock.System].
func WithClock(now clock.Clock) Option {
	return func(c *Challenger) {
		if now != nil {
			c.now = now
		}
	}
}

// WithHandleGenerator overrides the source of client-facing challenge
// handles. A nil generator is ignored. Defaults to [nonce.DefaultGenerator]
// (256-bit handles).
func WithHandleGenerator(g *nonce.Generator) Option {
	return func(c *Challenger) {
		if g != nil {
			c.handles = g
		}
	}
}

// WithLogger injects a structured logger for best-effort cleanup diagnostics.
// A nil logger is ignored. Defaults to [log.Discard], keeping the engine
// silent unless a logger is injected.
func WithLogger(logger *log.Logger) Option {
	return func(c *Challenger) {
		if logger != nil {
			c.logger = logger
		}
	}
}
