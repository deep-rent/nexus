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

package trust

import (
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/std/clock"
)

// DefaultLifetime is the trust window applied by [New] when [WithLifetime] is
// not given.
const DefaultLifetime = 30 * 24 * time.Hour

// Option configures a [Manager].
type Option func(*Manager)

// WithLifetime sets the trust window of a freshly issued token. Nonpositive
// values are ignored. Defaults to [DefaultLifetime].
func WithLifetime(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.lifetime = d
		}
	}
}

// WithHasher sets the hasher that fingerprints trust tokens before they reach
// the store. A nil hasher is ignored. Defaults to [digest.DefaultHasher].
func WithHasher(h *digest.Hasher) Option {
	return func(m *Manager) {
		if h != nil {
			m.hasher = h
		}
	}
}

// WithGenerator overrides the source of trust tokens. A nil generator is
// ignored. Defaults to [nonce.DefaultGenerator] (256-bit tokens).
func WithGenerator(g *nonce.Generator) Option {
	return func(m *Manager) {
		if g != nil {
			m.handles = g
		}
	}
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [clock.System].
func WithClock(now clock.Clock) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}
