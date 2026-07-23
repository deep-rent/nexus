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

package passkey

import (
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/nonce"
)

// Config carries the relying party settings for [New].
type Config struct {
	// RPID is the relying party identifier: the effective domain that
	// passkeys are scoped to (e.g., "example.com"). Native apps must be
	// associated with this domain (apple-app-site-association on iOS,
	// assetlinks.json on Android) to use the same passkeys. Required.
	RPID string
	// RPDisplayName is the human-palatable relying party name shown by
	// authenticators during ceremonies. Required.
	RPDisplayName string
	// RPOrigins lists the origins allowed to answer challenges. Web clients
	// appear as regular origins (e.g., "https://app.example.com"); Android
	// apps appear as "android:apk-key-hash:..." origins and must be listed
	// explicitly. Required.
	RPOrigins []string
	// Lifetime overrides [DefaultLifetime].
	Lifetime time.Duration
}

// Option configures a [RelyingParty].
type Option func(*RelyingParty)

// WithHasher sets the hasher that fingerprints ceremony handles before they
// reach the store. A nil hasher is ignored. Defaults to
// [digest.DefaultHasher].
func WithHasher(h *digest.Hasher) Option {
	return func(p *RelyingParty) {
		if h != nil {
			p.hasher = h
		}
	}
}

// WithHandleGenerator overrides the source of client-facing ceremony
// handles. A nil generator is ignored. Defaults to [nonce.DefaultGenerator]
// (256-bit handles).
func WithHandleGenerator(g *nonce.Generator) Option {
	return func(p *RelyingParty) {
		if g != nil {
			p.handles = g
		}
	}
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [time.Now].
func WithClock(now func() time.Time) Option {
	return func(p *RelyingParty) {
		if now != nil {
			p.now = now
		}
	}
}
