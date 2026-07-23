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

package session

import (
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/nonce"
)

// Option configures a [Manager].
type Option func(*Manager)

// WithHasher sets the hasher that fingerprints session keys before they
// reach the store. A nil hasher is ignored. Defaults to
// [digest.DefaultHasher].
func WithHasher(h *digest.Hasher) Option {
	return func(m *Manager) {
		if h != nil {
			m.hasher = h
		}
	}
}

// WithGenerator overrides the source of session keys. A nil generator is
// ignored. Defaults to [nonce.DefaultGenerator] (256-bit keys).
func WithGenerator(g *nonce.Generator) Option {
	return func(m *Manager) {
		if g != nil {
			m.keys = g
		}
	}
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [time.Now].
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}
