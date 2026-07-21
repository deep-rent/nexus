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
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/deep-rent/nexus/ascii"
	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/oauth/otp"
	"github.com/deep-rent/nexus/oauth/pkce"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/throttle"
	"github.com/deep-rent/nexus/vault"
)

// Default values applied by [New] for optional [Config] fields.
const (
	// DefaultRealm is the authentication realm announced in WWW-Authenticate
	// challenges.
	DefaultRealm = "oauth"
	// DefaultSessionCookieName names the cookie carrying the resource owner's
	// session key.
	DefaultSessionCookieName = "oauth_session"
	// DefaultStateCookieName names the cookie carrying the CSRF state during
	// external login flows.
	DefaultStateCookieName = "oauth_state"
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

// Config carries the mandatory dependencies and tunable settings for a
// [Server]. Zero values for optional fields are replaced with the package
// defaults by [New].
type Config struct {
	// Vault supplies the signing keys for access tokens and the public key
	// set served at the JWKS endpoint. Required.
	Vault vault.Vault
	// Clients bridges the server to the client registry. Required.
	Clients ClientStore
	// Sessions persists ephemeral authorization artifacts. Required.
	Sessions SessionStore
	// Subjects authenticates and resolves resource owners. Required.
	Subjects SubjectStore
	// Issuer is the canonical HTTPS URL of this authorization server. It is
	// embedded in the "iss" claim of issued tokens and announced in the
	// server metadata. Required.
	Issuer string
	// Realm is the authentication realm announced in WWW-Authenticate
	// challenges. Defaults to [DefaultRealm].
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
	// OTPCodeLength is the number of digits in a generated one-time
	// password. Defaults to [DefaultOTPCodeLength]. It is ignored when a
	// custom generator is installed via an [otp.WithCodeGenerator] passed to
	// [WithOTP]. Only relevant when two-factor logins are enabled via
	// [WithOTP].
	OTPCodeLength int
	// OTPLifetime overrides [DefaultOTPLifetime]. Resending a one-time
	// password does not extend a challenge's lifetime.
	OTPLifetime time.Duration
	// OTPMaxAttempts overrides [DefaultOTPMaxAttempts].
	OTPMaxAttempts int
	// OTPMaxResends overrides [DefaultOTPMaxResends]. A negative value
	// disables resends entirely.
	OTPMaxResends int
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
	// nil. Defaults to [DefaultThrottlePenalty].
	ThrottlePenalty int
	// Logger receives structured diagnostics. Defaults to [slog.Default].
	Logger *slog.Logger
}

// Server implements the endpoints of an OAuth 2.0 authorization server.
//
// Create instances with [New] and attach them to a router via
// [Server.Mount].
type Server struct {
	grants                 map[GrantType]Grant
	idps                   map[string]IdentityProvider
	vault                  vault.Vault
	clients                ClientStore
	sessions               SessionStore
	subjects               SubjectStore
	introspector           jwt.Verifier[*auth.Claims]
	issuer                 string
	sessionCookieName      string
	stateCookieName        string
	accessTokenLifetime    time.Duration
	refreshTokenLifetime   time.Duration
	authCodeLifetime       time.Duration
	deviceCodeLifetime     time.Duration
	devicePollInterval     time.Duration
	realm                  string
	loginTerminalURI       string
	loginRedirectURI       string
	generateSessionKey     TokenGeneratorFn
	generateAuthCode       TokenGeneratorFn
	generateRefreshToken   TokenGeneratorFn
	generateDeviceCode     TokenGeneratorFn
	generateUserCode       TokenGeneratorFn
	generateState          TokenGeneratorFn
	generateWebAuthnHandle TokenGeneratorFn
	verificationURI        string
	otpEnabled             bool
	otpOpts                []otp.Option
	otp                    *otp.Challenger
	webauthn               *webAuthnSupport
	throttle               *throttle.Throttle
	throttlePenalty        int
	logger                 *slog.Logger
	now                    func() time.Time
}

// Option customizes a [Server] during construction with [New].
type Option func(*Server)

// WithGrant registers a [Grant] implementation, enabling its grant type at
// the token endpoint.
func WithGrant(g Grant) Option {
	return func(s *Server) { s.grants[g.Type()] = g }
}

// WithIdentityProvider registers an external [IdentityProvider] under the
// given name. The name becomes the {provider} segment of the external login
// and callback paths.
func WithIdentityProvider(name string, idp IdentityProvider) Option {
	return func(s *Server) { s.idps[name] = idp }
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

// WithSessionKeyGenerator overrides [GenerateSessionKey].
func WithSessionKeyGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateSessionKey = fn }
}

// WithAuthCodeGenerator overrides [GenerateAuthCode].
func WithAuthCodeGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateAuthCode = fn }
}

// WithRefreshTokenGenerator overrides [GenerateRefreshToken].
func WithRefreshTokenGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateRefreshToken = fn }
}

// WithDeviceCodeGenerator overrides [GenerateDeviceCode].
func WithDeviceCodeGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateDeviceCode = fn }
}

// WithUserCodeGenerator overrides [GenerateUserCode].
func WithUserCodeGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateUserCode = fn }
}

// WithStateGenerator overrides [GenerateState].
func WithStateGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateState = fn }
}

// WithOTP enables two-factor logins.
//
// Once enabled, a successful password login by a subject with an enrolled
// [SecondFactor] (see [SubjectStore.GetSecondFactor]) no longer establishes a
// session directly. Instead, the server delivers a one-time password over one
// of the subject's enrolled [otp.Method] values and returns an
// [OTPChallengeResponse]; the client completes the login via [Server.VerifyOTP]
// and may switch channels via [Server.ResendOTP]. [Server.Mount] registers the
// verification and resend endpoints only when this option is present.
//
// Challenges are persisted through the server's [SessionStore] (its
// OTPChallenge methods). The flow is tuned via the OTP-prefixed fields of
// [Config]; pass [otp.Option] values such as [otp.WithCodeGenerator] or
// [otp.WithHandleGenerator] to override the generators.
func WithOTP(opts ...otp.Option) Option {
	return func(s *Server) {
		s.otpEnabled = true
		s.otpOpts = append(s.otpOpts, opts...)
	}
}

// WithWebAuthnHandleGenerator overrides [GenerateWebAuthnHandle].
func WithWebAuthnHandleGenerator(fn TokenGeneratorFn) Option {
	return func(s *Server) { s.generateWebAuthnHandle = fn }
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
	case cfg.Sessions == nil:
		panic("sessions is required")
	case cfg.Subjects == nil:
		panic("subjects is required")
	case cfg.Issuer == "":
		panic("issuer is required")
	}

	if _, err := url.Parse(cfg.Issuer); err != nil {
		panic("issuer is not a valid URL: " + err.Error())
	}
	if cfg.VerificationURI != "" {
		if _, err := url.Parse(cfg.VerificationURI); err != nil {
			panic("verification URI is not a valid URL: " + err.Error())
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		grants:   make(map[GrantType]Grant),
		idps:     make(map[string]IdentityProvider),
		vault:    cfg.Vault,
		clients:  cfg.Clients,
		sessions: cfg.Sessions,
		subjects: cfg.Subjects,
		issuer:   cfg.Issuer,
		sessionCookieName: cmp.Or(
			cfg.SessionCookieName,
			DefaultSessionCookieName,
		),
		stateCookieName: cmp.Or(
			cfg.StateCookieName,
			DefaultStateCookieName,
		),
		accessTokenLifetime: cmp.Or(
			cfg.AccessTokenLifetime,
			DefaultAccessTokenLifetime,
		),
		refreshTokenLifetime: cmp.Or(
			cfg.RefreshTokenLifetime,
			DefaultRefreshTokenLifetime,
		),
		authCodeLifetime: cmp.Or(
			cfg.AuthCodeLifetime,
			DefaultAuthCodeLifetime,
		),
		deviceCodeLifetime: cmp.Or(
			cfg.DeviceCodeLifetime,
			DefaultDeviceCodeLifetime,
		),
		devicePollInterval: cmp.Or(
			cfg.DevicePollInterval,
			DefaultDevicePollInterval,
		),
		realm:                  cmp.Or(cfg.Realm, DefaultRealm),
		loginTerminalURI:       cfg.LoginTerminalURI,
		loginRedirectURI:       cfg.LoginRedirectURI,
		verificationURI:        cfg.VerificationURI,
		generateSessionKey:     GenerateSessionKey,
		generateAuthCode:       GenerateAuthCode,
		generateRefreshToken:   GenerateRefreshToken,
		generateDeviceCode:     GenerateDeviceCode,
		generateUserCode:       GenerateUserCode,
		generateState:          GenerateState,
		generateWebAuthnHandle: GenerateWebAuthnHandle,
		throttle:               cfg.Throttle,
		throttlePenalty: cmp.Or(
			cfg.ThrottlePenalty,
			DefaultThrottlePenalty,
		),
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

	// The challenge engine is built only after all options are applied, so it
	// observes the final clock and logger. Caller-supplied otp.Options (from
	// WithOTP) win over the Config-derived defaults, since they are appended
	// last.
	if s.otpEnabled {
		s.otp = otp.New(
			otpStore{sessions: s.sessions, purpose: otpPurpose},
			append([]otp.Option{
				otp.WithCodeLength(cmp.Or(cfg.OTPCodeLength, DefaultOTPCodeLength)),
				otp.WithLifetime(cmp.Or(cfg.OTPLifetime, DefaultOTPLifetime)),
				otp.WithMaxAttempts(
					cmp.Or(cfg.OTPMaxAttempts, DefaultOTPMaxAttempts),
				),
				otp.WithMaxResends(
					cmp.Or(cfg.OTPMaxResends, DefaultOTPMaxResends),
				),
				otp.WithClock(s.now),
				otp.WithLogger(s.logger),
			}, s.otpOpts...)...,
		)
	}

	s.introspector = jwt.NewVerifier[*auth.Claims](
		s.vault.Keys(),
		jwt.WithIssuers(s.issuer),
		jwt.WithClock(s.now),
	)

	return s
}

// Supports checks whether the given grant type has been registered.
func (s *Server) Supports(grant GrantType) bool {
	_, ok := s.grants[grant]
	return ok
}

// Mount registers all endpoints of the server below the given path prefix.
//
// The device authorization endpoints are only registered when a verification
// URI has been configured, the external login endpoints only when at least
// one identity provider is registered, the OTP verification and resend
// endpoints only when two-factor logins are enabled via [WithOTP], and the
// WebAuthn endpoints only when passkey support is enabled via [WithWebAuthn].
//
// When [Config.Throttle] is set, every endpoint that verifies a credential
// — the token, revocation, introspection, login, device authorization, and
// device verification endpoints — is wrapped in the throttle middleware.
func (s *Server) Mount(r *router.Router, prefix string) {
	// guarded protects endpoints that accept credential guesses.
	var guarded []router.Middleware
	if s.throttle != nil {
		guarded = append(guarded, s.throttleMiddleware())
	}

	wellKnown := s.WellKnown(prefix)
	r.Handle(http.MethodGet+" "+prefix+PathWellKnown, wellKnown)

	// RFC 8414 Section 3: clients derive the metadata URL by inserting the
	// well-known path between the issuer's authority and path components.
	// Serve that location too whenever it differs from the prefixed route.
	if u, err := url.Parse(s.issuer); err == nil {
		root := PathWellKnown + strings.TrimSuffix(u.Path, "/")
		if root != prefix+PathWellKnown {
			r.Handle(http.MethodGet+" "+root, wellKnown)
		}
	}

	r.Handle(http.MethodGet+" "+prefix+PathKeySet, vault.Handler(s.vault))

	r.HandleFunc(http.MethodGet+" "+prefix+PathAuthorize, s.Authorize)
	r.HandleFunc(http.MethodPost+" "+prefix+PathAuthorize, s.Authorize)
	r.HandleFunc(http.MethodPost+" "+prefix+PathToken, s.Token, guarded...)
	r.HandleFunc(http.MethodPost+" "+prefix+PathRevoke, s.Revoke, guarded...)
	r.HandleFunc(
		http.MethodPost+" "+prefix+PathIntrospect,
		s.Introspect,
		guarded...,
	)
	r.HandleFunc(http.MethodPost+" "+prefix+PathLogin, s.Login, guarded...)
	r.HandleFunc(http.MethodPost+" "+prefix+PathLogout, s.Logout)

	if s.otp != nil {
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathLoginOTP,
			s.VerifyOTP,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathLoginOTPResend,
			s.ResendOTP,
			guarded...,
		)
	}

	if s.webauthn != nil {
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

	if s.verificationURI != "" {
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathDeviceAuthorization,
			s.DeviceAuthorization,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathDeviceVerify,
			s.DeviceVerify,
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

// WellKnown serves the OAuth 2.0 Authorization Server Metadata (RFC 8414)
// derived from the server configuration and the registered grants.
func (s *Server) WellKnown(prefix string) router.Handler {
	base := strings.TrimSuffix(s.issuer, "/") + prefix

	meta := AuthorizationServerMetadata{
		Issuer:                s.issuer,
		AuthorizationEndpoint: base + PathAuthorize,
		TokenEndpoint:         base + PathToken,
		KeySetURI:             base + PathKeySet,
		IntrospectionEndpoint: base + PathIntrospect,
		RevocationEndpoint:    base + PathRevoke,
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},
	}

	for g := range s.grants {
		meta.GrantTypesSupported = append(
			meta.GrantTypesSupported,
			string(g),
		)
	}
	slices.Sort(meta.GrantTypesSupported)

	if s.Supports(GrantTypeAuthorizationCode) {
		meta.ResponseTypesSupported = []string{"code"}
		meta.CodeChallengeMethodsSupported = []string{
			pkce.MethodS256,
			pkce.MethodPlain,
		}
	}

	if s.verificationURI != "" && s.Supports(GrantTypeDeviceCode) {
		meta.DeviceAuthorizationEndpoint = base + PathDeviceAuthorization
	}

	return router.HandlerFunc(func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, meta)
	})
}

// serverError returns an opaque internal [Error] carrying the given
// description and cause. The cause is logged, under a freshly assigned trace
// ID, when the response is written; see [Server.wrap].
func (s *Server) serverError(desc string, cause error) *Error {
	return &Error{
		Status:      http.StatusInternalServerError,
		Code:        ErrorCodeServerError,
		Description: desc,
		Cause:       cause,
	}
}

// throttled reports whether the given key has exhausted its throttle
// allowance, setting the Retry-After header when it has. It always reports
// false when throttling is disabled.
func (s *Server) throttled(e *router.Exchange, key string) bool {
	if s.throttle == nil {
		return false
	}
	blocked, wait := s.throttle.Blocked(key)
	if blocked {
		throttle.RetryAfter(e.W.Header(), wait)
	}
	return blocked
}

// penalize charges a failed authentication attempt against the given keys.
func (s *Server) penalize(keys ...string) {
	if s.throttle == nil {
		return
	}
	for _, key := range keys {
		s.throttle.Penalize(key, s.throttlePenalty)
	}
}

// clear restores the throttle allowance of a credential that has just been
// proven. Address-scoped keys are deliberately never cleared, so that
// holding one valid credential cannot wipe the penalty accrued while
// guessing others.
func (s *Server) clear(key string) {
	if s.throttle != nil {
		s.throttle.Reset(key)
	}
}

// throttleMiddleware spends one token per request from the requesting
// address's bucket, rejecting it with 429 once the bucket is empty. It keys
// by the same address scope as [Server.addr], so a request's baseline volume
// and the penalties its failed attempts accrue draw down one shared bucket.
func (s *Server) throttleMiddleware() router.Middleware {
	return s.throttle.MiddlewareFunc(func(r *http.Request) string {
		return scopeAddr + throttle.RemoteAddr(r)
	})
}

// addr returns the address-scoped throttle key for the request, or an empty
// string when throttling is disabled. It matches the key the throttle
// middleware spends against, so that per-request volume and per-attempt
// penalties share one bucket.
func (s *Server) addr(e *router.Exchange) string {
	if s.throttle == nil {
		return ""
	}
	return scopeAddr + throttle.RemoteAddr(e.R)
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
	return s.subjects.GetSubjectBySession(e.Context(), cookie.Value)
}

func (s *Server) authenticate(e *router.Exchange) (*Proposal, error) {
	data, err := e.ReadForm()
	if err != nil {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "failed to parse request body",
		}
	}

	clientID, clientSecret, ok := e.R.BasicAuth()
	if !ok {
		clientID = data.Get("client_id")
		clientSecret = data.Get("client_secret")
	} else {
		if data.Has("client_secret") {
			// RFC 6749 Section 2.3.1: MUST NOT use more than one auth method.
			return nil, &Error{
				Status:      http.StatusBadRequest,
				Code:        ErrorCodeInvalidRequest,
				Description: "multiple client authentication methods used",
			}
		}
		var err error
		clientID, err = url.QueryUnescape(clientID)
		if err != nil {
			s.challenge(e)
			return nil, &Error{
				Status:      http.StatusUnauthorized,
				Code:        ErrorCodeInvalidClient,
				Description: "invalid basic auth client id encoding",
			}
		}
		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			s.challenge(e)
			return nil, &Error{
				Status:      http.StatusUnauthorized,
				Code:        ErrorCodeInvalidClient,
				Description: "invalid basic auth client secret encoding",
			}
		}
		// Many client libraries redundantly include client_id in the body
		// alongside HTTP Basic authentication; tolerate it as long as it
		// names the same client.
		if id := data.Get("client_id"); id != "" && id != clientID {
			return nil, &Error{
				Status:      http.StatusBadRequest,
				Code:        ErrorCodeInvalidRequest,
				Description: "mismatched client id",
			}
		}
	}

	if clientID == "" {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "missing client id",
		}
	}

	// Repeated guesses against one client identity are locked out before
	// the store is consulted, regardless of the address they arrive from.
	clientKey := scopeClient + clientID
	if s.throttled(e, clientKey) {
		// Build an OAuth-shaped rejection returned once a the endpoint has
		// exhausted its throttle allowance.
		//
		// RFC 6749 defines no error code for rate limiting, so the device-flow
		// "slow_down" code (RFC 8628 Section 3.5) is reused: its semantics
		// match exactly, and clients that do not recognize it still honor the
		// 429 status and the accompanying Retry-After header.
		return nil, &Error{
			Status:      http.StatusTooManyRequests,
			Code:        ErrorCodeSlowDown,
			Description: "too many failed attempts",
		}
	}

	// deny records a failed credential attempt before returning the
	// (deliberately uniform) rejection.
	deny := func(desc string) (*Proposal, error) {
		s.penalize(clientKey, s.addr(e))
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: desc,
		}
	}

	// Client identifiers are UUIDs; a malformed value is indistinguishable
	// from an unknown client.
	id, err := uuid.Parse(clientID)
	if err != nil {
		return deny("unknown client")
	}

	client, err := s.clients.GetClient(e.Context(), id)
	if err != nil {
		return nil, s.serverError("failed to retrieve client", err)
	}

	if client == nil {
		return deny("unknown client")
	}

	if clientSecret == "" && !client.Public() {
		return deny("client requires a secret")
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		return deny("invalid client secret")
	}

	// The credential is proven; drop any penalty from earlier attempts.
	s.clear(clientKey)

	return &Proposal{
		Client:   client,
		Sessions: s.sessions,
		Logger:   s.logger,
		Now:      s.now,
		data:     data,
	}, nil
}

// challenge sets the WWW-Authenticate header to signal to the client that
// HTTP Basic authentication is required, as mandated by RFC 6749 Section 5.2
// for client authentication failures.
func (s *Server) challenge(e *router.Exchange) {
	e.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", s.realm))
}

// Introspect handles token introspection requests (RFC 7662).
//
// It allows authorized resource servers to query the metadata and active
// status of a given access token. The handler authenticates the client making
// the request and checks the provided token's validity against the server's
// key set. Public clients are rejected, as they could otherwise probe tokens
// they do not own.
func (s *Server) Introspect(e *router.Exchange) error {
	return s.wrap(e, s.introspect)
}

// introspect contains the logic for the token introspection endpoint.
func (s *Server) introspect(e *router.Exchange) error {
	pro, err := s.authenticate(e)
	if err != nil {
		return err
	}

	// RFC 7662 Section 2.1: introspection is reserved for protected
	// resources holding credentials.
	if pro.Client.Public() {
		return &Error{
			Status:      http.StatusForbidden,
			Code:        ErrorCodeUnauthorizedClient,
			Description: "public clients may not introspect tokens",
		}
	}

	token := pro.Get("token")
	if token == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing token",
		}
	}

	var res IntrospectionResponse

	if claims, err := s.introspector.Verify([]byte(token)); err != nil {
		s.logger.DebugContext(
			e.Context(),
			"Token verification failed during introspection",
			log.Err(err),
		)
	} else {
		res = IntrospectionResponse{
			Active:    true,
			TokenType: auth.Scheme,
			Scope:     claims.Scope.String(),
			Jti:       claims.Jti,
			Iss:       claims.Iss,
			Aud:       claims.Aud,
			Iat:       epoch(claims.IssuedAt()),
			Exp:       epoch(claims.ExpiresAt()),
			Nbf:       epoch(claims.NotBefore()),
		}
		if claims.Azp != "" {
			res.ClientID = claims.Azp
		}
		res.Sub = claims.Sub
	}

	return e.JSON(http.StatusOK, res)
}

// epoch converts a time to UNIX seconds, mapping the zero time to 0.
func epoch(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// Authorize handles requests to the authorization endpoint (RFC 6749
// Section 3.1).
//
// It supports both GET and POST requests. The handler validates the client
// identity, redirect URI, and requested scopes. If the resource owner
// has an active session (previously established via [Server.Login]), it
// generates an authorization code and redirects the user-agent back to
// the client's redirect URI.
func (s *Server) Authorize(e *router.Exchange) error {
	return s.wrap(e, s.authorize)
}

// authorize contains the logic for the authorization endpoint.
func (s *Server) authorize(e *router.Exchange) error {
	var data url.Values
	if e.Method() == http.MethodPost {
		form, err := e.ReadForm()
		if err != nil {
			return &Error{
				Status:      http.StatusBadRequest,
				Code:        ErrorCodeInvalidRequest,
				Description: "failed to parse request body",
			}
		}
		data = form
	} else {
		data = e.Query()
	}

	clientID := data.Get("client_id")
	if clientID == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing client id",
		}
	}

	// Client identifiers are UUIDs; a malformed value is indistinguishable
	// from an unknown client.
	id, err := uuid.Parse(clientID)
	if err != nil {
		return &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "client not found",
		}
	}

	client, err := s.clients.GetClient(e.Context(), id)
	if err != nil {
		return s.serverError("failed to retrieve client", err)
	}

	if client == nil {
		return &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "client not found",
		}
	}

	// If the redirect URI is missing or invalid, we MUST NOT redirect the
	// user-agent back to the client.
	// Instead, we inform the resource owner directly.
	redirectURI := data.Get("redirect_uri")
	if redirectURI == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing redirect uri",
		}
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "invalid redirect uri",
		}
	}

	if !client.VerifyRedirectURI(redirectURI) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "redirect uri not allowed for client",
		}
	}

	responseType := data.Get("response_type")
	scope := data.Get("scope")
	state := data.Get("state")
	codeChallenge := data.Get("code_challenge")
	codeChallengeMethod := data.Get("code_challenge_method")

	fail := func(code, desc string) error {
		q := u.Query()
		q.Set("error", code)
		q.Set("error_description", desc)
		// RFC 6749 Section 4.1.2.1: The state parameter is REQUIRED if it
		// was present in the client authorization request.
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		return e.Redirect(u.String(), http.StatusFound)
	}

	switch {
	case responseType != "code":
		return fail(
			ErrorCodeUnsupportedResponseType,
			"unsupported response type",
		)
	case !client.CanUseGrant(GrantTypeAuthorizationCode):
		return fail(
			ErrorCodeUnauthorizedClient,
			"client is not allowed to use authorization code grant",
		)
	case scope != "" && !canUseScope(client, scope):
		return fail(
			ErrorCodeInvalidScope,
			"requested scope is not allowed for this client",
		)
	case codeChallenge == "":
		return fail(
			ErrorCodeInvalidRequest,
			"code challenge is required",
		)
	case codeChallengeMethod == "":
		return fail(
			ErrorCodeInvalidRequest,
			"code challenge method is required",
		)
	case !pkce.Supports(codeChallengeMethod):
		return fail(
			ErrorCodeInvalidRequest,
			"unsupported code challenge method",
		)
	}

	// Authenticate the resource owner using the session cookie established by
	// the login endpoint.
	sub, err := s.subjectFromSession(e)
	if err != nil {
		return s.serverError("failed to lookup subject", err)
	}

	if sub == nil {
		return fail(
			ErrorCodeAccessDenied,
			"resource owner is not authenticated",
		)
	}

	code, err := s.generateAuthCode(e.Context())
	if err != nil {
		return s.serverError("failed to generate authorization code",
			err,
		)
	}

	if err := s.sessions.CreateAuthCode(
		e.Context(),
		AuthCode{
			Code:                NewDigest(code),
			ClientID:            client.ID(),
			RedirectURI:         redirectURI,
			Scope:               scope,
			SubjectID:           sub.ID(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ExpiresAt:           s.now().Add(s.authCodeLifetime).Unix(),
		},
	); err != nil {
		return s.serverError("failed to store authorization code",
			err,
		)
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	return e.Redirect(u.String(), http.StatusFound)
}

// Token handles requests to the token endpoint (RFC 6749 Section 3.2).
//
// It authenticates the requesting client (via HTTP Basic or POST parameters)
// and processes the specified grant type using the [Grant] implementations
// previously registered via [WithGrant]. Returns a JSON response containing an
// access token and optional refresh token.
func (s *Server) Token(e *router.Exchange) error {
	return s.wrap(e, s.token)
}

// token contains the logic for the token endpoint.
func (s *Server) token(e *router.Exchange) error {
	pro, err := s.authenticate(e)
	if err != nil {
		return err
	}

	grantType := GrantType(pro.Get("grant_type"))
	if grantType == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing grant type",
		}
	}

	grant, ok := s.grants[grantType]
	if !ok {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeUnsupportedGrantType,
			Description: "unsupported grant type",
		}
	}

	if !pro.Client.CanUseGrant(grantType) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeUnauthorizedClient,
			Description: "client is not allowed to use this grant type",
		}
	}

	iss, err := grant.Authorize(e.Context(), pro)
	if err != nil {
		return err
	}

	now := s.now()
	clientID := pro.Client.ID()

	claims := &auth.Claims{
		Azp:   clientID.String(),
		Scope: strings.Fields(iss.Scope),
		Jti:   uuid.New().String(),
		Iss:   s.issuer,
		Aud:   pro.Client.Audience(),
		Iat:   now,
		Nbf:   now,
		Exp:   now.Add(s.accessTokenLifetime),
	}

	// Populate claims based on the context of the grant.
	if iss.Subject == uuid.Nil() {
		claims.Sub = clientID.String() // The subject is the client itself
	} else if sub, err := s.subjects.GetSubject(
		e.Context(),
		iss.Subject,
	); err != nil {
		return s.serverError("failed to retrieve subject", err)
	} else if sub != nil {
		claims.Sub = sub.ID().String()
		claims.Roles = sub.Roles()
	} else {
		s.logger.ErrorContext(
			e.Context(),
			"Subject not found for claims",
			slog.String("subject", iss.Subject.String()),
		)

		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "subject no longer available",
		}
	}

	key := s.vault.Next()
	if key == nil {
		return s.serverError("unable to obtain signing key",
			errors.New("vault returned no signing key"),
		)
	}

	token, err := jwt.Sign(e.Context(), key, claims)
	if err != nil {
		return s.serverError("failed to mint access token", err)
	}

	res := TokenResponse{
		AccessToken: string(token),
		TokenType:   auth.Scheme,
		ExpiresIn:   int64(s.accessTokenLifetime.Seconds()),
		Scope:       iss.Scope,
	}

	if iss.Refreshable &&
		s.Supports(GrantTypeRefreshToken) &&
		pro.Client.CanUseGrant(GrantTypeRefreshToken) {
		token, err := s.generateRefreshToken(e.Context())
		if err != nil {
			return s.serverError("failed to generate refresh token",
				err,
			)
		}

		if err := s.sessions.CreateRefreshToken(e.Context(), RefreshToken{
			Token:     NewDigest(token),
			ClientID:  clientID,
			SubjectID: iss.Subject,
			Scope:     cmp.Or(iss.RefreshScope, iss.Scope),
			ExpiresAt: now.Add(s.refreshTokenLifetime).Unix(),
		}); err != nil {
			return s.serverError("failed to save refresh token",
				err,
			)
		}

		res.RefreshToken = token
	}

	return e.JSON(http.StatusOK, res)
}

// Revoke handles token revocation requests per RFC 7009.
//
// It allows clients to signal that a previously obtained refresh token is no
// longer needed. The handler authenticates the client and, if the provided
// token is a valid refresh token belonging to that client, removes it from the
// [SessionStore].
func (s *Server) Revoke(e *router.Exchange) error {
	return s.wrap(e, s.revoke)
}

// revoke contains the logic for token revocation.
func (s *Server) revoke(e *router.Exchange) error {
	pro, err := s.authenticate(e)
	if err != nil {
		return err
	}

	token := pro.Get("token")
	if token == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing token",
		}
	}

	// The store only ever sees the digest of the token.
	digest := NewDigest(token)

	// Validate token ownership before revocation per RFC 7009 Section 2.1
	r, err := s.sessions.GetRefreshToken(e.Context(), digest)
	if err != nil {
		return s.serverError("failed to retrieve token", err)
	}
	if r.Token == "" || r.ClientID != pro.Client.ID() {
		// Token not found or belongs to another client. Return 200 OK.
		e.Status(http.StatusOK)
		return nil
	}

	if _, err := s.sessions.DeleteRefreshToken(
		e.Context(),
		digest,
	); err != nil {
		s.logger.ErrorContext(
			e.Context(),
			"Failed to delete refresh token during revocation",
			log.Err(err),
		)
	}

	e.Status(http.StatusOK)

	return nil
}

// DeviceAuthorization handles requests to the device authorization endpoint
// (RFC 8628 Section 3.1).
//
// It authenticates the client and issues a device code and a user code,
// which the client displays to the resource owner.
//
// Note: This endpoint requires a valid [Config.VerificationURI] to be
// provided during server initialization.
func (s *Server) DeviceAuthorization(e *router.Exchange) error {
	return s.wrap(e, s.deviceAuthorization)
}

// deviceAuthorization contains the logic for device authorization requests.
func (s *Server) deviceAuthorization(e *router.Exchange) error {
	if s.verificationURI == "" {
		e.Status(http.StatusNotFound)
		return nil
	}

	pro, err := s.authenticate(e)
	if err != nil {
		return err
	}

	if !pro.Client.CanUseGrant(GrantTypeDeviceCode) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeUnauthorizedClient,
			Description: "client is not allowed to use device code grant",
		}
	}

	scope := pro.Get("scope")
	if scope != "" && !canUseScope(pro.Client, scope) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	deviceCode, err := s.generateDeviceCode(e.Context())
	if err != nil {
		return s.serverError("failed to generate device code",
			err,
		)
	}

	userCode, err := s.generateUserCode(e.Context())
	if err != nil {
		return s.serverError("failed to generate user code", err)
	}

	interval := int64(s.devicePollInterval.Seconds())

	// The user code is digested in its canonical form so that the lookup in
	// DeviceVerify (which normalizes user input the same way) always
	// matches, regardless of the generator's output format.
	if err := s.sessions.CreateDeviceCode(e.Context(), DeviceCode{
		DeviceCode: NewDigest(deviceCode),
		UserCode:   NewDigest(normalizeUserCode(userCode)),
		ClientID:   pro.Client.ID(),
		Scope:      scope,
		Status:     DeviceCodeStatusPending,
		ExpiresAt:  s.now().Add(s.deviceCodeLifetime).Unix(),
		Interval:   interval,
	}); err != nil {
		return s.serverError("failed to store device code", err)
	}

	// Config.VerificationURI is validated during construction, so parsing
	// cannot fail here. Building the complete URI through url.Values keeps
	// it correct even when the configured URI already carries a query.
	complete, err := url.Parse(s.verificationURI)
	if err != nil {
		return s.serverError("invalid verification URI", err)
	}
	q := complete.Query()
	q.Set("user_code", userCode)
	complete.RawQuery = q.Encode()

	res := DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         s.verificationURI,
		VerificationURIComplete: complete.String(),
		ExpiresIn:               int64(s.deviceCodeLifetime.Seconds()),
		Interval:                interval,
	}

	return e.JSON(http.StatusOK, res)
}

// DeviceVerify lets an authenticated resource owner approve or deny a
// pending device authorization request (RFC 8628 Section 3.3).
//
// The resource owner is identified via the session cookie established by
// [Server.Login]. The request payload is a [DeviceVerificationRequest]
// carrying the user code displayed on the device and the desired action.
func (s *Server) DeviceVerify(e *router.Exchange) error {
	sub, err := s.subjectFromSession(e)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "login required",
		}
	}

	var req DeviceVerificationRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	// RFC 8628 Section 5.1: user codes are short enough to be guessed, so
	// the verification endpoint must be rate limited. The session holder is
	// throttled rather than the code, since an attacker guessing codes
	// controls their own session but not the codes they hit.
	subjectKey := scopeCode + sub.ID().String()
	if s.throttled(e, subjectKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	code, err := s.sessions.GetDeviceCodeByUserCode(
		e.Context(),
		NewDigest(normalizeUserCode(req.UserCode)),
	)
	if err != nil {
		return router.ServerError("failed to retrieve device code",
			err,
		)
	}

	if code.DeviceCode == "" ||
		(code.ExpiresAt != 0 && s.now().Unix() > code.ExpiresAt) {
		s.penalize(subjectKey, s.addr(e))
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      router.ReasonNotFound,
			Description: "unknown or expired user code",
		}
	}

	if code.Status != DeviceCodeStatusPending {
		return &router.Error{
			Status:      http.StatusConflict,
			Reason:      router.ReasonValidationFailed,
			Description: "device authorization request is no longer pending",
		}
	}

	if req.Action == DeviceVerificationApprove {
		code.Status = DeviceCodeStatusAuthorized
		code.SubjectID = sub.ID()
	} else {
		code.Status = DeviceCodeStatusDenied
	}

	if err := s.sessions.UpdateDeviceCode(e.Context(), code); err != nil {
		return router.ServerError("failed to update device code",
			err,
		)
	}

	e.NoContent()

	return nil
}

// normalizeUserCode canonicalizes a user code: embedded whitespace is
// stripped, letters are uppercased, and a missing hyphen is re-inserted for
// the default XXXX-XXXX format produced by [GenerateUserCode]. It is applied
// both when storing the code digest and when looking up user input, so
// custom generators work as long as their output is stable under this
// canonicalization.
func normalizeUserCode(code string) string {
	code = ascii.ToUpper(strings.Join(strings.Fields(code), ""))
	if !strings.Contains(code, "-") && len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}
	return code
}

// wrap executes the handler and translates any returned [Error] into an HTTP
// JSON response using the error's defined status code.
//
// This is the error boundary for the RFC 6749 error shape, and therefore the
// one place that logs it: handlers and grants return errors, they do not
// report them. Errors that are not an [Error] fall through to the router,
// which logs them the same way.
func (s *Server) wrap(
	e *router.Exchange,
	handler func(*router.Exchange) error,
) error {
	// RFC 6749 Sections 5.1 and 5.2: responses containing tokens or error
	// details must not be cached. This applies to error responses as well,
	// so the headers are set up front.
	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")

	err := handler(e)
	oerr, ok := errors.AsType[*Error](err)
	if !ok {
		return err
	}

	// A server error is the kind a client may quote back in a bug report, so
	// it always carries an identifier that can be found in the logs.
	if oerr.ID == "" && oerr.Status >= http.StatusInternalServerError {
		oerr.ID = router.ErrorID()
	}

	s.record(e, oerr)

	return e.JSON(oerr.Status, oerr)
}

// record logs a failed OAuth exchange. Server errors are reported at error
// level; the protocol errors that make up normal traffic (invalid_grant,
// invalid_client and friends) are recorded at debug level so they do not
// drown the logs.
func (s *Server) record(e *router.Exchange, oerr *Error) {
	ctx := e.Context()

	level := slog.LevelDebug
	if oerr.Status >= http.StatusInternalServerError {
		level = slog.LevelError
	}

	if !s.logger.Enabled(ctx, level) {
		return
	}

	attrs := []any{
		slog.Int("status", oerr.Status),
		slog.String("code", oerr.Code),
		slog.String("path", e.Path()),
	}
	if oerr.ID != "" {
		attrs = append(attrs, slog.String("error_id", oerr.ID))
	}
	if oerr.Cause != nil {
		attrs = append(attrs, log.Err(oerr.Cause))
	}

	s.logger.Log(ctx, level, oerr.Description, attrs...)
}
