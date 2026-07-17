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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/pkce"
	"github.com/deep-rent/nexus/router"
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
	// Logger receives structured diagnostics. Defaults to [slog.Default].
	Logger *slog.Logger
}

// Server implements the endpoints of an OAuth 2.0 authorization server.
//
// Create instances with [New] and attach them to a router via
// [Server.Mount].
type Server struct {
	grants               map[GrantType]Grant
	idps                 map[string]IdentityProvider
	vault                vault.Vault
	clients              ClientStore
	sessions             SessionStore
	subjects             SubjectStore
	introspector         jwt.Verifier[*auth.Claims]
	issuer               string
	sessionCookieName    string
	stateCookieName      string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	authCodeLifetime     time.Duration
	deviceCodeLifetime   time.Duration
	devicePollInterval   time.Duration
	realm                string
	loginTerminalURI     string
	loginRedirectURI     string
	generateSessionKey   TokenGeneratorFn
	generateAuthCode     TokenGeneratorFn
	generateRefreshToken TokenGeneratorFn
	generateDeviceCode   TokenGeneratorFn
	generateUserCode     TokenGeneratorFn
	generateState        TokenGeneratorFn
	verificationURI      string
	logger               *slog.Logger
	clock                func() time.Time
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
			s.clock = now
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

// New assembles a [Server] from the given configuration and options.
//
// It returns an error if a required [Config] field is missing, or if
// identity providers are registered without the login URIs they depend on.
func New(cfg Config, opts ...Option) (*Server, error) {
	switch {
	case cfg.Vault == nil:
		return nil, errors.New("oauth: Config.Vault is required")
	case cfg.Clients == nil:
		return nil, errors.New("oauth: Config.Clients is required")
	case cfg.Sessions == nil:
		return nil, errors.New("oauth: Config.Sessions is required")
	case cfg.Subjects == nil:
		return nil, errors.New("oauth: Config.Subjects is required")
	case cfg.Issuer == "":
		return nil, errors.New("oauth: Config.Issuer is required")
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
		realm:                cmp.Or(cfg.Realm, DefaultRealm),
		loginTerminalURI:     cfg.LoginTerminalURI,
		loginRedirectURI:     cfg.LoginRedirectURI,
		verificationURI:      cfg.VerificationURI,
		generateSessionKey:   GenerateSessionKey,
		generateAuthCode:     GenerateAuthCode,
		generateRefreshToken: GenerateRefreshToken,
		generateDeviceCode:   GenerateDeviceCode,
		generateUserCode:     GenerateUserCode,
		generateState:        GenerateState,
		logger:               logger,
		clock:                time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	if len(s.idps) > 0 &&
		(s.loginTerminalURI == "" || s.loginRedirectURI == "") {
		return nil, errors.New(
			"oauth: Config.LoginTerminalURI and Config.LoginRedirectURI are " +
				"required when identity providers are registered",
		)
	}

	s.introspector = jwt.NewVerifier[*auth.Claims](
		s.vault.Keys(),
		jwt.WithIssuers(s.issuer),
		jwt.WithClock(s.clock),
	)

	return s, nil
}

// Supports checks whether the given grant type has been registered.
func (s *Server) Supports(grant GrantType) bool {
	_, ok := s.grants[grant]
	return ok
}

// Mount registers all endpoints of the server below the given path prefix.
//
// The device authorization endpoints are only registered when a verification
// URI has been configured, and the external login endpoints only when at
// least one identity provider is registered.
func (s *Server) Mount(r *router.Router, prefix string) {
	r.Handle(http.MethodGet+" "+prefix+PathWellKnown, s.WellKnown(prefix))
	r.Handle(http.MethodGet+" "+prefix+PathKeySet, vault.Handler(s.vault))

	r.HandleFunc(http.MethodGet+" "+prefix+PathAuthorize, s.Authorize)
	r.HandleFunc(http.MethodPost+" "+prefix+PathAuthorize, s.Authorize)
	r.HandleFunc(http.MethodPost+" "+prefix+PathToken, s.Token)
	r.HandleFunc(http.MethodPost+" "+prefix+PathRevoke, s.Revoke)
	r.HandleFunc(http.MethodPost+" "+prefix+PathIntrospect, s.Introspect)
	r.HandleFunc(http.MethodPost+" "+prefix+PathLogin, s.Login)
	r.HandleFunc(http.MethodPost+" "+prefix+PathLogout, s.Logout)

	if s.verificationURI != "" {
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathDeviceAuthorization,
			s.DeviceAuthorization,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathDeviceVerify,
			s.DeviceVerify,
		)
	}

	if len(s.idps) > 0 {
		r.HandleFunc(
			http.MethodGet+" "+prefix+PathExternalLogin,
			s.ExternalLogin,
		)
		r.HandleFunc(
			http.MethodGet+" "+prefix+PathExternalCallback,
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

// serverError logs err under a fresh trace ID and returns an opaque internal
// [Error] carrying the same trace ID and description.
func (s *Server) serverError(
	ctx context.Context,
	desc string,
	err error,
) *Error {
	id := router.ErrorID()

	s.logger.ErrorContext(
		ctx,
		desc,
		slog.String("error_id", id),
		slog.Any("error", err),
	)

	return &Error{
		Status:      http.StatusInternalServerError,
		Code:        ErrorCodeServerError,
		Description: desc,
		ID:          id,
	}
}

// internalError is the [router.Error] counterpart of serverError, used by
// the first-party endpoints (login, logout, device verification).
func (s *Server) internalError(
	ctx context.Context,
	desc string,
	err error,
) *router.Error {
	id := router.ErrorID()

	s.logger.ErrorContext(
		ctx,
		desc,
		slog.String("error_id", id),
		slog.Any("error", err),
	)

	return &router.Error{
		Status:      http.StatusInternalServerError,
		Reason:      router.ReasonServerError,
		Description: desc,
		ID:          id,
	}
}

// newCookie builds a hardened cookie shared by the session and state flows.
// A maxAge of zero yields a browser-session cookie; negative values delete
// the cookie on the user-agent.
func (s *Server) newCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
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
		if data.Has("client_id") || data.Has("client_secret") {
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
	}

	if clientID == "" {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "missing client id",
		}
	}

	// Client identifiers are UUIDs; a malformed value is indistinguishable
	// from an unknown client.
	id, err := uuid.Parse(clientID)
	if err != nil {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "unknown client",
		}
	}

	client, err := s.clients.GetClient(e.Context(), id)
	if err != nil {
		return nil, s.serverError(e.Context(), "failed to retrieve client", err)
	}

	if client == nil {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "unknown client",
		}
	}

	if clientSecret == "" && !client.Public() {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "client requires a secret",
		}
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "invalid client secret",
		}
	}

	return &Proposal{
		Client:   client,
		Sessions: s.sessions,
		Logger:   s.logger,
		Now:      s.clock,
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
	return wrap(e, s.introspect)
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
			slog.Any("error", err),
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
		if claims.Azp != uuid.Nil() {
			res.ClientID = claims.Azp.String()
		}
		if claims.Sub != uuid.Nil() {
			res.Sub = claims.Sub.String()
		}
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
	return wrap(e, s.authorize)
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
		return s.serverError(e.Context(), "failed to retrieve client", err)
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
		return s.serverError(e.Context(), "failed to lookup subject", err)
	}

	if sub == nil {
		return fail(
			ErrorCodeAccessDenied,
			"resource owner is not authenticated",
		)
	}

	code, err := s.generateAuthCode(e.Context())
	if err != nil {
		return s.serverError(
			e.Context(),
			"failed to generate authorization code",
			err,
		)
	}

	if err := s.sessions.CreateAuthCode(
		e.Context(),
		AuthCode{
			Code:                code,
			ClientID:            client.ID(),
			RedirectURI:         redirectURI,
			Scope:               scope,
			SubjectID:           sub.ID(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ExpiresAt:           s.clock().Add(s.authCodeLifetime).Unix(),
		},
	); err != nil {
		return s.serverError(
			e.Context(),
			"failed to store authorization code",
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
	return wrap(e, s.token)
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

	now := s.clock()
	clientID := pro.Client.ID()

	claims := &auth.Claims{
		Azp:   clientID,
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
		claims.Sub = clientID // The subject is the client itself
	} else if sub, err := s.subjects.GetSubject(
		e.Context(),
		iss.Subject,
	); err != nil {
		return s.serverError(e.Context(), "failed to retrieve subject", err)
	} else if sub != nil {
		claims.Sub = sub.ID()
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
		return s.serverError(
			e.Context(),
			"unable to obtain signing key",
			errors.New("vault returned no signing key"),
		)
	}

	token, err := jwt.Sign(e.Context(), key, claims)
	if err != nil {
		return s.serverError(e.Context(), "failed to mint access token", err)
	}

	res := TokenResponse{
		AccessToken: string(token),
		TokenType:   auth.Scheme,
		ExpiresIn:   uint64(s.accessTokenLifetime.Seconds()),
		Scope:       iss.Scope,
	}

	if iss.Refreshable && s.Supports(GrantTypeRefreshToken) {
		token, err := s.generateRefreshToken(e.Context())
		if err != nil {
			return s.serverError(
				e.Context(),
				"failed to generate refresh token",
				err,
			)
		}

		if err := s.sessions.CreateRefreshToken(e.Context(), RefreshToken{
			Token:     token,
			ClientID:  clientID,
			SubjectID: iss.Subject,
			Scope:     iss.Scope,
			ExpiresAt: now.Add(s.refreshTokenLifetime).Unix(),
		}); err != nil {
			return s.serverError(
				e.Context(),
				"failed to save refresh token",
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
	return wrap(e, s.revoke)
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

	// Validate token ownership before revocation per RFC 7009 Section 2.1
	r, err := s.sessions.GetRefreshToken(e.Context(), token)
	if err != nil {
		return s.serverError(e.Context(), "failed to retrieve token", err)
	}
	if r.Token == "" || r.ClientID != pro.Client.ID() {
		// Token not found or belongs to another client. Return 200 OK.
		e.Status(http.StatusOK)
		return nil
	}

	if err := s.sessions.DeleteRefreshToken(e.Context(), token); err != nil {
		s.logger.ErrorContext(
			e.Context(),
			"Failed to delete refresh token during revocation",
			slog.Any("error", err),
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
	return wrap(e, s.deviceAuthorization)
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
		return s.serverError(
			e.Context(),
			"failed to generate device code",
			err,
		)
	}

	userCode, err := s.generateUserCode(e.Context())
	if err != nil {
		return s.serverError(e.Context(), "failed to generate user code", err)
	}

	interval := int64(s.devicePollInterval.Seconds())

	if err := s.sessions.CreateDeviceCode(e.Context(), DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   pro.Client.ID(),
		Scope:      scope,
		Status:     DeviceCodeStatusPending,
		ExpiresAt:  s.clock().Add(s.deviceCodeLifetime).Unix(),
		Interval:   interval,
	}); err != nil {
		return s.serverError(e.Context(), "failed to store device code", err)
	}

	res := DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.verificationURI,
		VerificationURIComplete: s.verificationURI +
			"?user_code=" + url.QueryEscape(userCode),
		ExpiresIn: int(s.deviceCodeLifetime.Seconds()),
		Interval:  int(interval),
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
		return s.internalError(e.Context(), "failed to lookup subject", err)
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

	code, err := s.sessions.GetDeviceCodeByUserCode(
		e.Context(),
		normalizeUserCode(req.UserCode),
	)
	if err != nil {
		return s.internalError(
			e.Context(),
			"failed to retrieve device code",
			err,
		)
	}

	if code.DeviceCode == "" ||
		(code.ExpiresAt != 0 && s.clock().Unix() > code.ExpiresAt) {
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
		return s.internalError(
			e.Context(),
			"failed to update device code",
			err,
		)
	}

	e.NoContent()

	return nil
}

// normalizeUserCode canonicalizes user input for user code lookups: embedded
// whitespace is stripped, letters are uppercased, and a missing hyphen is
// re-inserted for the default XXXX-XXXX format produced by
// [GenerateUserCode].
func normalizeUserCode(code string) string {
	code = strings.ToUpper(strings.Join(strings.Fields(code), ""))
	if !strings.Contains(code, "-") && len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}
	return code
}

// wrap executes the handler and translates any returned [Error] into an HTTP
// JSON response using the error's defined status code.
func wrap(e *router.Exchange, handler func(*router.Exchange) error) error {
	// RFC 6749 Sections 5.1 and 5.2: responses containing tokens or error
	// details must not be cached. This applies to error responses as well,
	// so the headers are set up front.
	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")

	err := handler(e)
	if v, ok := errors.AsType[*Error](err); ok {
		return e.JSON(v.Status, v)
	}
	return err
}
