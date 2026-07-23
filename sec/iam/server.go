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
	"cmp"
	"context"
	"net/http"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/net/throttle"
	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/flow"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/internal/limit"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/otp"
	"github.com/deep-rent/nexus/sec/iam/passkey"
	"github.com/deep-rent/nexus/sec/iam/session"
	"github.com/deep-rent/nexus/sec/iam/trust"
	"github.com/deep-rent/nexus/sec/jose/jwt"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/sys/log"
)

// Server implements the endpoints of an OAuth 2.0 authorization server.
//
// Create instances with [New] and attach them to a router via
// [Server.Mount].
type Server struct {
	oauth                     *oauth.Server
	grantList                 []oauth.Grant
	idps                      map[string]idp.Provider
	stores                    Stores
	subjects                  SubjectStore
	introspector              jwt.Verifier[*auth.Claims]
	sessionCookieName         string
	stateCookieName           string
	trustCookieName           string
	loginTerminalURI          string
	loginRedirectURI          string
	nonceSource               nonce.Source
	nonce                     *nonce.Generator
	planner                   Planner
	sessions                  *session.Manager
	sessionLifetime           time.Duration
	passwordless              bool
	otpOpts                   []otp.Option
	flow                      *flow.Coordinator
	otp                       *otp.Challenger
	rememberedSessionLifetime time.Duration
	trustedDeviceLifetime     time.Duration
	trust                     *trust.Manager
	passkeyCfg                *passkey.Config
	passkeys                  *passkey.RelyingParty
	hasher                    *digest.Hasher
	throttle                  *throttle.Throttle
	throttlePenalty           int
	limit                     limit.Limiter
	logger                    *log.Logger
	now                       func() time.Time
}

// New assembles a [Server] from the given configuration and options.
//
// It panics if a required [Config] field is missing, or if identity
// providers are registered without the login URIs they depend on. Server
// construction happens once at startup, so misconfiguration is a programmer
// error rather than a recoverable runtime condition.
func New(cfg Config, opts ...Option) *Server {
	switch {
	case cfg.Vault == nil:
		panic("vault is required")
	case cfg.Clients == nil:
		panic("clients is required")
	case cfg.Stores.AuthCodes == nil:
		panic("auth code store is required")
	case cfg.Stores.RefreshTokens == nil:
		panic("refresh token store is required")
	case cfg.Stores.Sessions == nil:
		panic("session store is required")
	case cfg.Subjects == nil:
		panic("subjects is required")
	case cfg.Issuer == "":
		panic("issuer is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.Discard()
	}

	s := &Server{
		idps:     make(map[string]idp.Provider),
		stores:   cfg.Stores,
		subjects: cfg.Subjects,
		sessionCookieName: cmp.Or(
			cfg.SessionCookieName,
			DefaultSessionCookieName,
		),
		stateCookieName: cmp.Or(
			cfg.StateCookieName,
			DefaultStateCookieName,
		),
		trustCookieName: cmp.Or(
			cfg.TrustCookieName,
			DefaultTrustCookieName,
		),
		sessionLifetime: cmp.Or(
			cfg.SessionLifetime,
			DefaultSessionLifetime,
		),
		rememberedSessionLifetime: cmp.Or(
			cfg.RememberedSessionLifetime,
			DefaultRememberedSessionLifetime,
		),
		trustedDeviceLifetime: cmp.Or(
			cfg.TrustedDeviceLifetime,
			DefaultTrustedDeviceLifetime,
		),
		loginTerminalURI: cfg.LoginTerminalURI,
		loginRedirectURI: cfg.LoginRedirectURI,
		throttle:         cfg.Throttle,
		throttlePenalty: cmp.Or(
			cfg.ThrottlePenalty,
			oauth.DefaultThrottlePenalty,
		),
		hasher: digest.DefaultHasher,
		logger: logger,
		now:    time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	if len(s.idps) > 0 &&
		(s.loginTerminalURI == "" || s.loginRedirectURI == "") {
		panic(
			"Config.LoginTerminalURI and Config.LoginRedirectURI are " +
				"required when identity providers are registered",
		)
	}

	if s.passwordless && s.planner == nil {
		panic("WithPasswordless requires WithFlow")
	}

	switch {
	case s.planner != nil && s.stores.Challenges == nil:
		panic("WithFlow requires Stores.Challenges")
	case s.planner != nil && s.stores.Flows == nil:
		panic("WithFlow requires Stores.Flows")
	case s.planner != nil && s.stores.Trust == nil:
		panic("WithFlow requires Stores.Trust")
	case s.passkeyCfg != nil && s.stores.Ceremonies == nil:
		panic("WithPasskeys requires Stores.Ceremonies")
	case s.passkeyCfg != nil && s.stores.Credentials == nil:
		panic("WithPasskeys requires Stores.Credentials")
	case cfg.VerificationURI != "" && s.stores.DeviceCodes == nil:
		panic("Config.VerificationURI requires Stores.DeviceCodes")
	}

	s.limit = limit.New(s.throttle, s.throttlePenalty)

	// Every opaque bearer artifact the login machinery mints — session keys,
	// state parameters, WebAuthn handles, and device trust tokens — is drawn
	// from one generator fed by the configured source (crypto/rand by
	// default). It is built after the options so it observes the final
	// source.
	s.nonce = nonce.NewGenerator(s.nonceSource, oauth.NonceSize)

	// The session engine shares the server's nonce generator, hasher, and
	// clock; per-session lifetimes are decided at establishment.
	s.sessions = session.New(
		s.stores.Sessions,
		session.WithHasher(s.hasher),
		session.WithGenerator(s.nonce),
		session.WithClock(s.now),
	)

	// The device trust engine shares the server's nonce generator, hasher,
	// and clock. It is built only when a trust store is configured; servers
	// without one simply treat every device as untrusted.
	if s.stores.Trust != nil {
		s.trust = trust.New(
			s.stores.Trust,
			trust.WithLifetime(s.trustedDeviceLifetime),
			trust.WithHasher(s.hasher),
			trust.WithGenerator(s.nonce),
			trust.WithClock(s.now),
		)
	}

	// The login engines are built only after all options are applied, so they
	// observe the final clock, hasher, and logger. The OTP challenge lifetime
	// doubles as the flow lifetime, so a code stays live for as long as the
	// login it backs. Caller-supplied otp.Options (from WithFlow) win over the
	// Config-derived defaults, since they are appended last.
	if s.planner != nil {
		lifetime := cmp.Or(cfg.OTPLifetime, DefaultOTPLifetime)
		s.otp = otp.New(
			s.stores.Challenges,
			append([]otp.Option{
				otp.WithCodeSampler(nonce.NewSampler(
					nil,
					otp.Digits,
					cmp.Or(cfg.OTPCodeLength, DefaultOTPCodeLength),
				)),
				otp.WithLifetime(lifetime),
				otp.WithMaxAttempts(
					cmp.Or(cfg.OTPMaxAttempts, DefaultOTPMaxAttempts),
				),
				otp.WithMaxResends(
					cmp.Or(cfg.OTPMaxResends, DefaultOTPMaxResends),
				),
				otp.WithHasher(s.hasher),
				otp.WithClock(s.now),
				otp.WithLogger(s.logger),
			}, s.otpOpts...)...,
		)
		s.flow = flow.New(
			s.stores.Flows,
			flow.WithLifetime(lifetime),
			flow.WithHasher(s.hasher),
			flow.WithClock(s.now),
			flow.WithLogger(s.logger),
		)
	}

	// The passkey relying party shares the server's nonce generator, hasher,
	// and clock, and registers the WebAuthn token grant on the embedded
	// authorization server.
	if s.passkeyCfg != nil {
		s.passkeys = passkey.New(
			*s.passkeyCfg,
			s.stores.Ceremonies,
			s.stores.Credentials,
			subjectDirectory{s},
			passkey.WithHasher(s.hasher),
			passkey.WithHandleGenerator(s.nonce),
			passkey.WithClock(s.now),
		)
		s.grantList = append(s.grantList, &webAuthnGrant{s})
	}

	// The embedded authorization server handles the OAuth token machinery.
	// It observes the same clock, hasher, entropy source, and throttle as
	// the login machinery, and reaches back into it only through the
	// session and owner resolver seams.
	srvOpts := []oauth.ServerOption{
		oauth.WithClock(s.now),
		oauth.WithHasher(s.hasher),
	}
	if s.nonceSource != nil {
		srvOpts = append(srvOpts, oauth.WithNonceSource(s.nonceSource))
	}
	for _, g := range s.grantList {
		srvOpts = append(srvOpts, oauth.WithGrant(g))
	}
	s.oauth = oauth.NewServer(oauth.ServerConfig{
		Vault:   cfg.Vault,
		Clients: cfg.Clients,
		Tokens:  cfg.Stores.TokenStores,
		Sessions: func(e *router.Exchange) (oauth.Owner, error) {
			sub, err := s.subjectFromSession(e)
			if err != nil || sub == nil {
				return nil, err
			}
			return sub, nil
		},
		Owners: func(
			ctx context.Context,
			id uuid.UUID,
		) (oauth.Owner, error) {
			sub, err := s.subjects.GetSubject(ctx, id)
			if err != nil || sub == nil {
				return nil, err
			}
			return sub, nil
		},
		Issuer:               cfg.Issuer,
		Realm:                cfg.Realm,
		VerificationURI:      cfg.VerificationURI,
		AccessTokenLifetime:  cfg.AccessTokenLifetime,
		RefreshTokenLifetime: cfg.RefreshTokenLifetime,
		AuthCodeLifetime:     cfg.AuthCodeLifetime,
		DeviceCodeLifetime:   cfg.DeviceCodeLifetime,
		DevicePollInterval:   cfg.DevicePollInterval,
		Throttle:             s.throttle,
		ThrottlePenalty:      s.throttlePenalty,
		Logger:               s.logger,
	}, srvOpts...)

	s.introspector = jwt.NewVerifier[*auth.Claims](
		cfg.Vault.Keys(),
		jwt.WithIssuers(cfg.Issuer),
		jwt.WithClock(s.now),
	)

	return s
}

// OAuth returns the embedded [oauth.Server] handling the token machinery.
func (s *Server) OAuth() *oauth.Server { return s.oauth }

// Supports checks whether the given grant type has been registered on the
// embedded authorization server.
func (s *Server) Supports(grant oauth.GrantType) bool {
	return s.oauth.Supports(grant)
}

// Mount registers all endpoints of the server below the given path prefix.
//
// The device authorization endpoints are only registered when a verification
// URI has been configured, the external login endpoints only when at least
// one identity provider is registered, the login continue and action
// endpoints only when a multi-step login is enabled via [WithFlow], and the
// WebAuthn endpoints only when passkey support is enabled via [WithPasskeys].
//
// When [Config.Throttle] is set, every endpoint that verifies a credential
// — the token, revocation, introspection, login, device authorization, and
// device verification endpoints — is wrapped in the throttle middleware.
func (s *Server) Mount(r *router.Router, prefix string) {
	// The token machinery mounts through the embedded authorization server.
	s.oauth.Mount(r, prefix)

	// guarded protects endpoints that accept credential guesses.
	var guarded []router.Middleware
	if s.limit.Enabled() {
		guarded = append(guarded, s.limit.Middleware())
	}

	r.HandleFunc(http.MethodPost+" "+prefix+PathLogin, s.Login, guarded...)
	r.HandleFunc(http.MethodPost+" "+prefix+PathLogout, s.Logout)

	if s.flow != nil {
		if s.passwordless {
			r.HandleFunc(
				http.MethodPost+" "+prefix+PathLoginIdentify,
				s.Identify,
				guarded...,
			)
		}
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathLoginContinue,
			s.Continue,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathLoginAction,
			s.Action,
			guarded...,
		)
	}

	if s.passkeys != nil {
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathWebAuthnRegisterOptions,
			s.WebAuthnRegisterOptions,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathWebAuthnRegister,
			s.WebAuthnRegister,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathWebAuthnLoginOptions,
			s.WebAuthnLoginOptions,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathWebAuthnLogin,
			s.WebAuthnLogin,
			guarded...,
		)
	}

	if len(s.idps) > 0 {
		r.HandleFunc(
			http.MethodGet+" "+prefix+PathExternalLogin,
			s.ExternalLogin,
		)
		// Callbacks arrive as GET (query response mode) or POST (form_post
		// response mode, e.g. Sign in with Apple).
		r.HandleFunc(
			http.MethodGet+" "+prefix+PathExternalCallback,
			s.ExternalCallback,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathExternalCallback,
			s.ExternalCallback,
		)
	}
}

// throttled reports whether the given key has exhausted its throttle
// allowance; see [limit.Limiter].
func (s *Server) throttled(e *router.Exchange, key string) bool {
	return s.limit.Throttled(e, key)
}

// penalize charges a failed authentication attempt against the given keys.
func (s *Server) penalize(keys ...string) {
	s.limit.Penalize(keys...)
}

// clear restores the throttle allowance of a credential that has just been
// proven; see [limit.Limiter].
func (s *Server) clear(key string) {
	s.limit.Clear(key)
}

// addr returns the address-scoped throttle key for the request, or an empty
// string when throttling is disabled; see [limit.Limiter].
func (s *Server) addr(e *router.Exchange) string {
	return s.limit.Addr(e)
}

// newSessionCookie builds the cookie carrying the resource owner's session
// key. SameSite=Lax keeps the cookie out of cross-site subrequests while
// still covering top-level navigations to the authorization endpoint.
func (s *Server) newSessionCookie(value string, maxAge int) *http.Cookie {
	return router.NewCookie(
		s.sessionCookieName,
		value,
		maxAge,
		http.SameSiteLaxMode,
	)
}

// newTrustCookie builds the remember-me device trust cookie. A negative maxAge
// clears it on the user-agent.
func (s *Server) newTrustCookie(value string, maxAge int) *http.Cookie {
	return router.NewCookie(
		s.trustCookieName,
		value,
		maxAge,
		http.SameSiteLaxMode,
	)
}

// newStateCookie builds the CSRF state cookie for external login flows. It
// opts out of same-site enforcement because providers using the form_post
// response mode (e.g., Sign in with Apple) deliver the callback as a
// cross-site POST, which would not carry a Lax cookie.
func (s *Server) newStateCookie(value string, maxAge int) *http.Cookie {
	return router.NewCookie(
		s.stateCookieName,
		value,
		maxAge,
		http.SameSiteNoneMode,
	)
}

// subjectFromSession resolves the resource owner bound to the session cookie.
//
// It returns nil (with a nil error) if no valid session exists, and an error
// only if the underlying storage lookup fails.
func (s *Server) subjectFromSession(e *router.Exchange) (Subject, error) {
	cookie, err := e.Cookie(s.sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, nil
	}
	owner, ok, err := s.sessions.Resolve(e.Context(), cookie.Value)
	if err != nil || !ok {
		return nil, err
	}
	return s.subjectOf(e.Context(), owner)
}

// digest fingerprints a bearer artifact with the server's configured hasher;
// see [WithHasher].
func (s *Server) digest(value string) oauth.Digest {
	return oauth.Digest(s.hasher.String(value))
}
