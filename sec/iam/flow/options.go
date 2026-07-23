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

package flow

import (
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/sys/log"
)

// DefaultLifetime is the validity period of a login transaction applied by
// [New] when [WithLifetime] is not given. It bounds the whole multi-step login,
// independent of any per-step lifetime.
const DefaultLifetime = 10 * time.Minute

// Option configures a [Coordinator].
type Option func(*Coordinator)

// WithLifetime sets the validity period of a login transaction. Nonpositive
// values are ignored. Defaults to [DefaultLifetime].
func WithLifetime(d time.Duration) Option {
	return func(c *Coordinator) {
		if d > 0 {
			c.lifetime = d
		}
	}
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [time.Now].
func WithClock(now func() time.Time) Option {
	return func(c *Coordinator) {
		if now != nil {
			c.now = now
		}
	}
}

// WithHandleGenerator overrides the source of client-facing transaction
// handles. A nil generator is ignored. Defaults to [nonce.DefaultGenerator]
// (256-bit handles).
func WithHandleGenerator(g *nonce.Generator) Option {
	return func(c *Coordinator) {
		if g != nil {
			c.handles = g
		}
	}
}

// WithHasher sets the hasher that fingerprints transaction handles before
// they reach the store. A nil hasher is ignored. Defaults to
// [digest.DefaultHasher].
func WithHasher(h *digest.Hasher) Option {
	return func(c *Coordinator) {
		if h != nil {
			c.hasher = h
		}
	}
}

// WithLogger injects a structured logger for best-effort cleanup diagnostics.
// A nil logger is ignored. Defaults to [log.Discard], keeping the engine
// silent unless a logger is injected.
func WithLogger(logger *log.Logger) Option {
	return func(c *Coordinator) {
		if logger != nil {
			c.logger = logger
		}
	}
}
