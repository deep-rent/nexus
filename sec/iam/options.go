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

package iam

import (
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/otp"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/sec/vault"
	"github.com/deep-rent/nexus/net/throttle"
)

// Config holds the mandatory and optional parameters for constructing a
// [Server]. Zero values for optional fields are replaced with the package
// defaults by [New].
type Config struct {
	// Vault supplies the signing keys for access tokens and the public key
	// set served at the JWKS endpoint. Required.
	Vault vault.Vault
	// Clients bridges the server to the client registry. Required.
	Clients oauth.ClientStore
	// Stores bundles the persistence backends for ephemeral artifacts.
	// The embedded token stores are always required; the login stores are
	// required by the options that use them (see [Stores]).
	Stores Stores
	// Subjects authenticates and resolves resource owners. Required.
	Subjects SubjectStore
	// Issuer is the canonical HTTPS URL of this authorization server. It is
	// embedded in the "iss" claim of issued tokens and announced in the
	// server metadata. Required.
	Issuer string
	// Realm is the authentication realm announced in WWW-Authenticate
	// challenges. Defaults to [oauth.DefaultRealm].
	Realm string
	// LoginTerminalURI locates the frontend login page. The external
	// callback redirects here with error details when a social login fails.
	// Required if identity providers are registered.
	LoginTerminalURI string
	// LoginRedirectURI is the destination after a successful external login.
	// Required if identity providers are registered.
	LoginRedirectURI string
	// VerificationURI locates the frontend page where resource owners enter
	// device user codes. Setting it enables the device authorization
	// endpoints.
	VerificationURI string
	// SessionCookieName overrides [DefaultSessionCookieName].
	SessionCookieName string
	// StateCookieName overrides [DefaultStateCookieName].
	StateCookieName string
	// TrustCookieName overrides [DefaultTrustCookieName].
	TrustCookieName string
	// AccessTokenLifetime overrides [oauth.DefaultAccessTokenLifetime].
	AccessTokenLifetime time.Duration
	// RefreshTokenLifetime overrides [oauth.DefaultRefreshTokenLifetime].
	RefreshTokenLifetime time.Duration
	// AuthCodeLifetime overrides [oauth.DefaultAuthCodeLifetime].
	AuthCodeLifetime time.Duration
	// DeviceCodeLifetime overrides [oauth.DefaultDeviceCodeLifetime].
	DeviceCodeLifetime time.Duration
	// DevicePollInterval overrides [oauth.DefaultDevicePollInterval].
	DevicePollInterval time.Duration
	// OTPCodeLength is the number of digits in a generated one-time
	// password. Defaults to [DefaultOTPCodeLength]. It is ignored when a
	// custom sampler is installed via an [otp.WithCodeSampler] passed to
	// [WithFlow]. Only relevant for the one-time password steps of a login
	// flow enabled via [WithFlow].
	OTPCodeLength int
	// OTPLifetime overrides [DefaultOTPLifetime]. Resending a one-time
	// password does not extend a challenge's lifetime.
	OTPLifetime time.Duration
	// OTPMaxAttempts overrides [DefaultOTPMaxAttempts].
	OTPMaxAttempts int
	// OTPMaxResends overrides [DefaultOTPMaxResends]. A negative value
	// disables resends entirely.
	OTPMaxResends int
	// SessionLifetime is the server-side validity period of a session
	// established without the remember flag. The session cookie itself
	// remains a browser-session cookie; this bounds how long the session
	// stays resolvable on the server. Defaults to [DefaultSessionLifetime].
	SessionLifetime time.Duration
	// RememberedSessionLifetime is how long a session persists when the client
	// asked to be remembered at login. It sets both the Max-Age of the
	// persistent session cookie and the server-side expiry; without the
	// remember flag, SessionLifetime applies instead. Defaults to
	// [DefaultRememberedSessionLifetime].
	RememberedSessionLifetime time.Duration
	// TrustedDeviceLifetime is how long a remember-me device trust token stays
	// valid. On a trusted device within this window, a [Planner] may skip
	// factors. Defaults to [DefaultTrustedDeviceLifetime].
	TrustedDeviceLifetime time.Duration
	// Throttle rate limits the credential-verifying endpoints and applies
	// escalating penalties to failed authentication attempts. When set,
	// [Server.Mount] guards those routes with per-address limiting
	// automatically, and the server charges failed attempts against the
	// address, client, user, and code buckets of the same throttle. A nil
	// value disables throttling.
	//
	// The server derives its own bucket keys, so any [throttle.Config.Key] is
	// ignored; configure only the rate and burst.
	Throttle *throttle.Throttle
	// ThrottlePenalty is the number of tokens a single failed authentication
	// attempt charges against its buckets. Larger values lock out brute-force
	// attempts sooner. It should stay below the throttle's burst so that one
	// failure does not exhaust a bucket outright. Ignored when Throttle is
	// nil. Defaults to [oauth.DefaultThrottlePenalty].
	ThrottlePenalty int
	// Logger receives structured diagnostics. Defaults to [slog.Default].
	Logger *slog.Logger
}

// Option customizes a [Server] during construction with [New].
type Option func(*Server)

// WithGrant registers an [oauth.Grant] implementation, enabling its grant
// type at the token endpoint of the embedded authorization server.
func WithGrant(g oauth.Grant) Option {
	return func(s *Server) { s.grantList = append(s.grantList, g) }
}

// WithIdentityProvider registers an external [idp.Provider] under the
// given name. The name becomes the {provider} segment of the external login
// and callback paths.
func WithIdentityProvider(name string, p idp.Provider) Option {
	return func(s *Server) { s.idps[name] = p }
}

// WithHasher sets the hasher that fingerprints every bearer artifact before
// it crosses a store boundary — authorization codes, refresh tokens, device
// and user codes, WebAuthn handles, device trust tokens, login flow handles,
// and one-time passwords. A nil hasher is ignored. Defaults to
// [digest.DefaultHasher] (SHA-256, base64url).
//
// The hasher is wired through to the grants (via [oauth.Proposal.Digest]) and
// the login engines, so a single configuration applies consistently across
// the server. Changing it invalidates every previously stored artifact.
func WithHasher(h *digest.Hasher) Option {
	return func(s *Server) {
		if h != nil {
			s.hasher = h
		}
	}
}

// WithClock overrides the server's time source. This is primarily useful for
// deterministic testing.
func WithClock(now func() time.Time) Option {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// WithNonceSource sets the entropy source for every opaque bearer artifact the
// server mints — session keys, authorization codes, refresh tokens, device and
// user codes, state parameters, WebAuthn handles, and device trust tokens — all
// of which are drawn from a single [nonce.Generator] (a [nonce.Sampler] for user
// codes). It defaults to [nonce.DefaultSource] (crypto/rand); provide a
// deterministic source for testing or a hardware/remote source in specialized
// deployments. A nil source is ignored.
//
// It does not affect the one-time password steps of a login flow, whose
// generators are configured through [WithFlow].
func WithNonceSource(src nonce.Source) Option {
	return func(s *Server) {
		if src != nil {
			s.nonceSource = src
		}
	}
}

// WithFlow enables multi-step logins driven by the given [Planner].
//
// Once enabled, a successful password login no longer establishes a session
// directly. Instead the server runs the planner to decide the remaining
// authentication steps for the subject and device, and — if any remain —
// returns a [FlowResponse] carrying a flow handle. The client satisfies each
// step via [Server.Continue] and may drive out-of-band actions (such as
// resending a code) via [Server.Action], carrying the handle throughout.
// [Server.Mount] registers the continue and action endpoints only when this
// option is present.
//
// Flow transactions and one-time password challenges are persisted through
// [Stores.Flows] and [Stores.Challenges]. The OTP steps are tuned via the
// OTP-prefixed fields
// of [Config]; pass [otp.Option] values such as [otp.WithCodeSampler] or
// [otp.WithHandleGenerator] to override the generators. It panics if planner is
// nil, since that is a startup configuration error.
func WithFlow(planner Planner, opts ...otp.Option) Option {
	return func(s *Server) {
		if planner == nil {
			panic("planner is required")
		}
		s.planner = planner
		s.otpOpts = append(s.otpOpts, opts...)
	}
}

// WithPasswordless additionally enables passwordless login, in which a subject
// is identified by username alone and the flow's factors — rather than a
// password — authenticate them. It requires [WithFlow] and registers the
// [Server.Identify] endpoint.
//
// The same [Planner] serves both entries, so its chain must be sufficient
// authentication on its own; passwordless login ignores device trust and
// refuses to establish a session when the planner yields no factors, so it can
// never authenticate on a username alone. See [Server.Identify] for the
// enumeration considerations of exposing a username-keyed endpoint.
func WithPasswordless() Option {
	return func(s *Server) { s.passwordless = true }
}
