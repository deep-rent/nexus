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
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/net/throttle"
	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/sec/vault"
)

// Default values applied by [NewServer] for optional [ServerConfig] fields.
const (
	// DefaultRealm is the authentication realm announced in WWW-Authenticate
	// challenges.
	DefaultRealm = "oauth"
	// DefaultAccessTokenLifetime is the validity period of access tokens.
	DefaultAccessTokenLifetime = 1 * time.Hour
	// DefaultRefreshTokenLifetime is the validity period of refresh tokens.
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour
	// DefaultAuthCodeLifetime is the validity period of authorization codes.
	DefaultAuthCodeLifetime = 10 * time.Minute
	// DefaultDeviceCodeLifetime is the validity period of device codes.
	DefaultDeviceCodeLifetime = 15 * time.Minute
	// DefaultDevicePollInterval is the minimum delay between device code
	// polling attempts.
	DefaultDevicePollInterval = 5 * time.Second
	// DefaultThrottlePenalty is the number of tokens charged against a
	// throttle bucket for a single failed authentication attempt.
	DefaultThrottlePenalty = 10
)

// ServerConfig carries the mandatory dependencies and tunable settings for a
// [Server]. Zero values for optional fields are replaced with the package
// defaults by [NewServer].
type ServerConfig struct {
	// Vault supplies the signing keys for access tokens and the public key
	// set served at the JWKS endpoint. Required.
	Vault vault.Vault
	// Clients bridges the server to the client registry. Required.
	Clients ClientStore
	// Tokens bundles the persistence backends for the token-issuance
	// artifacts. AuthCodes and RefreshTokens are always required;
	// DeviceCodes is required when VerificationURI is set.
	Tokens TokenStores
	// Sessions authenticates the resource owner behind a request. Required
	// when the Authorization Code grant is offered or VerificationURI is
	// set; a machine-to-machine deployment may leave it nil.
	Sessions SessionResolver
	// Owners resolves resource owners for claim minting. Required whenever a
	// registered grant names a resource owner (every grant except Client
	// Credentials).
	Owners OwnerResolver
	// Issuer is the canonical HTTPS URL of this authorization server. It is
	// embedded in the "iss" claim of issued tokens and announced in the
	// server metadata. Required.
	Issuer string
	// Realm is the authentication realm announced in WWW-Authenticate
	// challenges. Defaults to [DefaultRealm].
	Realm string
	// VerificationURI locates the frontend page where resource owners enter
	// device user codes. Setting it enables the device authorization
	// endpoints.
	VerificationURI string
	// AccessTokenLifetime overrides [DefaultAccessTokenLifetime].
	AccessTokenLifetime time.Duration
	// RefreshTokenLifetime overrides [DefaultRefreshTokenLifetime].
	RefreshTokenLifetime time.Duration
	// AuthCodeLifetime overrides [DefaultAuthCodeLifetime].
	AuthCodeLifetime time.Duration
	// DeviceCodeLifetime overrides [DefaultDeviceCodeLifetime].
	DeviceCodeLifetime time.Duration
	// DevicePollInterval overrides [DefaultDevicePollInterval].
	DevicePollInterval time.Duration
	// Throttle rate limits the credential-verifying endpoints and applies
	// escalating penalties to failed authentication attempts. When set,
	// [Server.Mount] guards those routes with per-address limiting
	// automatically. A nil value disables throttling. When this server is
	// composed with a login system, both should share one throttle so
	// penalties draw down the same buckets.
	//
	// The server derives its own bucket keys, so any [throttle.Config.Key]
	// is ignored; configure only the rate and burst.
	Throttle *throttle.Throttle
	// ThrottlePenalty is the number of tokens a single failed authentication
	// attempt charges against its buckets. Larger values lock out
	// brute-force attempts sooner. It should stay below the throttle's burst
	// so that one failure does not exhaust a bucket outright. Ignored when
	// Throttle is nil. Defaults to [DefaultThrottlePenalty].
	ThrottlePenalty int
	// Logger receives structured diagnostics. Defaults to [slog.Default].
	Logger *slog.Logger
}

// ServerOption customizes a [Server] during construction with [NewServer].
type ServerOption func(*Server)

// WithGrant registers a [Grant] implementation, enabling its grant type at
// the token endpoint.
func WithGrant(g Grant) ServerOption {
	return func(s *Server) { s.grants[g.Type()] = g }
}

// WithHasher sets the hasher that fingerprints every bearer artifact before
// it crosses a store boundary — authorization codes, refresh tokens, and
// device and user codes. A nil hasher is ignored. Defaults to
// [digest.DefaultHasher] (SHA-256, base64url).
//
// The hasher is wired through to the grants via [Proposal.Digest], so a
// single configuration applies consistently across the server and its
// grants. Changing it invalidates every previously stored artifact.
func WithHasher(h *digest.Hasher) ServerOption {
	return func(s *Server) {
		if h != nil {
			s.hasher = h
		}
	}
}

// WithClock overrides the server's time source. This is primarily useful for
// deterministic testing.
func WithClock(now func() time.Time) ServerOption {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// WithNonceSource sets the entropy source for every opaque bearer artifact
// the server mints — authorization codes, refresh tokens, and device and
// user codes — all of which are drawn from a single [nonce.Generator] (a
// [nonce.Sampler] for user codes). It defaults to [nonce.DefaultSource]
// (crypto/rand); provide a deterministic source for testing or a
// hardware/remote source in specialized deployments. A nil source is
// ignored.
func WithNonceSource(src nonce.Source) ServerOption {
	return func(s *Server) {
		if src != nil {
			s.nonceSource = src
		}
	}
}
