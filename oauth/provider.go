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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/internal/pkce"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

const (
	// DefaultSessionCookieName is the default name for the cookie used to
	// track the resource owner's session.
	DefaultSessionCookieName = "oauth_session"
	// DefaultStateCookieName is the default name for the cookie used to
	// store the OAuth 2.0 state parameter during external login flows.
	DefaultStateCookieName = "oauth_state"
	// DefaultAccessTokenLifetime is the default duration for which an
	// access token is valid.
	DefaultAccessTokenLifetime = 5 * time.Minute
	// DefaultRefreshTokenLifetime is the default duration for which a
	// refresh token is valid.
	DefaultRefreshTokenLifetime = 7 * 24 * time.Hour
	// DefaultAuthCodeLifetime is the default duration for which an
	// authorization code is valid.
	DefaultAuthCodeLifetime = 10 * time.Minute
	// DefaultDeviceCodeLifetime is the default duration for which a
	// device code is valid.
	DefaultDeviceCodeLifetime = 15 * time.Minute
	// DefaultRealm is the default authentication realm name used in
	// WWW-Authenticate headers.
	DefaultRealm = "OAuth2"
)

// Config holds the configuration options for an OAuth 2.0 Provider.
type Config struct {
	// Signer is the JWT signer used to issue access tokens.
	// This option is mandatory.
	Signer jwt.Signer
	// Verifier is the JWT verifier used to validate tokens.
	// Optional; if omitted, token introspection will not be deactivated.
	Verifier jwt.Verifier[*auth.Claims]
	// Clients provides access to registered client applications.
	// This option is mandatory.
	Clients ClientStore
	// Sessions provides access to authorization artifacts (codes, refresh tokens).
	// This option is mandatory.
	Sessions SessionStore
	// Subjects provides access to resource owner identities and sessions.
	// This option is mandatory.
	Subjects SubjectStore
	// Logger is the structured logger used by the provider.
	// Optional; defaults to [slog.Default].
	Logger *slog.Logger
	// SessionCookieName is the name of the session cookie.
	// Optional; defaults to [DefaultSessionCookieName].
	SessionCookieName string
	// StateCookieName is the name of the cookie used to store the state
	// parameter during external login flows.
	// Optional; defaults to [DefaultStateCookieName].
	StateCookieName string
	// AccessTokenLifetime defines how long issued access tokens remain valid.
	// Optional; defaults to [DefaultAccessTokenLifetime].
	AccessTokenLifetime time.Duration
	// RefreshTokenLifetime defines how long issued refresh tokens remain valid.
	// Optional; defaults to [DefaultRefreshTokenLifetime].
	RefreshTokenLifetime time.Duration
	// AuthCodeLifetime defines how long issued authorization codes remain valid.
	// Optional; defaults to [DefaultAuthCodeLifetime].
	AuthCodeLifetime time.Duration
	// DeviceCodeLifetime defines how long issued device codes remain valid.
	// Optional; defaults to [DefaultDeviceCodeLifetime].
	DeviceCodeLifetime time.Duration
	// Realm is the authentication realm name for challenges.
	// Optional; defaults to [DefaultRealm].
	Realm string
	// VerificationURI is the user-facing URL where resource owners enter the
	// user code to authorize a device. This field is mandatory if the
	// [GrantTypeDeviceCode] is registered via [WithGrant].
	VerificationURI string
	// LoginPageURI is the frontend URL where users are directed to log in.
	// This is used for redirects during external auth failures or session
	// timeouts. Required if identity providers are configured.
	LoginPageURI string
	// LoginRedirectURI is the URL where resource owners are redirected after
	// a successful social login flow. Required if identity providers are
	// configured.
	LoginRedirectURI string
	// GenerateOpaqueToken overrides the default string generator used for
	// authorization codes, refresh tokens, device codes, and session keys.
	// Defaults to [GenerateOpaqueToken].
	GenerateOpaqueToken func() (string, error)
	// GenerateUserCode overrides the default string generator for device flow
	// user codes. Defaults to [GenerateUserCode].
	GenerateUserCode func() (string, error)
}

// Option defines a functional configuration pattern for a [Provider].
type Option func(*Provider)

// WithIdentityProvider returns an [Option] that registers an external
// identity provider for social login flows.
//
// The name parameter identifies the provider in the URL paths (e.g., "google"
// results in a login path of /oauth/login/google). If identity providers
// are registered, the [Config.LoginRedirectURI] must be provided in the
// initial configuration.
func WithIdentityProvider(name string, impl IdentityProvider) Option {
	return func(p *Provider) {
		p.identityProviders[name] = impl
	}
}

// WithGrant returns an [Option] that enables a specific OAuth 2.0 grant
// flow on the provider.
//
// This allows the provider to process token requests for the associated
// [GrantType].
func WithGrant(grant Grant) Option {
	return func(p *Provider) {
		p.grants[grant.Type()] = grant
	}
}

// Provider is the central component that manages OAuth 2.0 flows, token
// issuance, and validation.
type Provider struct {
	signer               jwt.Signer
	verifier             jwt.Verifier[*auth.Claims]
	clients              ClientStore
	sessions             SessionStore
	subjects             SubjectStore
	grants               map[GrantType]Grant
	identityProviders    map[string]IdentityProvider
	logger               *slog.Logger
	sessionCookieName    string
	stateCookieName      string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	authCodeLifetime     time.Duration
	deviceCodeLifetime   time.Duration
	realm                string
	verificationURI      string
	issuer               string
	loginPageURI         *url.URL
	loginRedirectURI     string
	generateOpaqueToken  func() (string, error)
	generateUserCode     func() (string, error)
}

// NewProvider creates a new OAuth 2.0 provider with the specified
// configuration.
//
// It panics if any mandatory options are missing.
func NewProvider(cfg Config, opts ...Option) *Provider {
	if cfg.Signer == nil {
		panic("oauth: signer is required")
	}
	if cfg.Clients == nil {
		panic("oauth: client store is required")
	}
	if cfg.Sessions == nil {
		panic("oauth: session store is required")
	}
	if cfg.Subjects == nil {
		panic("oauth: subject store is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	sessionCookieName := cfg.SessionCookieName
	if sessionCookieName == "" {
		sessionCookieName = DefaultSessionCookieName
	}

	stateCookieName := cfg.StateCookieName
	if stateCookieName == "" {
		stateCookieName = DefaultStateCookieName
	}

	accessTokenLifetime := cfg.AccessTokenLifetime
	if accessTokenLifetime <= 0 {
		accessTokenLifetime = DefaultAccessTokenLifetime
	}

	refreshTokenLifetime := cfg.RefreshTokenLifetime
	if refreshTokenLifetime <= 0 {
		refreshTokenLifetime = DefaultRefreshTokenLifetime
	}

	authCodeLifetime := cfg.AuthCodeLifetime
	if authCodeLifetime <= 0 {
		authCodeLifetime = DefaultAuthCodeLifetime
	}

	deviceCodeLifetime := cfg.DeviceCodeLifetime
	if deviceCodeLifetime <= 0 {
		deviceCodeLifetime = DefaultDeviceCodeLifetime
	}

	realm := cfg.Realm
	if realm == "" {
		realm = DefaultRealm
	}

	issuer := ""
	if iss := strings.TrimRight(cfg.Signer.Issuer(), "/"); iss != "" {
		if u, err := url.Parse(iss); err == nil {
			if u.Scheme != "" && u.Host != "" {
				issuer = iss
			}
		}
	}

	generateOpaqueToken := cfg.GenerateOpaqueToken
	if generateOpaqueToken == nil {
		generateOpaqueToken = GenerateOpaqueToken
	}

	generateUserCode := cfg.GenerateUserCode
	if generateUserCode == nil {
		generateUserCode = GenerateUserCode
	}

	var loginPageURI *url.URL
	if cfg.LoginPageURI != "" {
		u, err := url.Parse(cfg.LoginPageURI)
		if err != nil {
			panic(fmt.Errorf("oauth: invalid login page uri: %w", err))
		}
		loginPageURI = u
	}

	p := &Provider{
		signer:               cfg.Signer,
		verifier:             cfg.Verifier,
		clients:              cfg.Clients,
		sessions:             cfg.Sessions,
		subjects:             cfg.Subjects,
		grants:               make(map[GrantType]Grant),
		identityProviders:    make(map[string]IdentityProvider),
		logger:               logger,
		sessionCookieName:    sessionCookieName,
		stateCookieName:      stateCookieName,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		authCodeLifetime:     authCodeLifetime,
		deviceCodeLifetime:   deviceCodeLifetime,
		realm:                realm,
		verificationURI:      cfg.VerificationURI,
		loginPageURI:         loginPageURI,
		loginRedirectURI:     cfg.LoginRedirectURI,
		issuer:               issuer,
		generateOpaqueToken:  generateOpaqueToken,
		generateUserCode:     generateUserCode,
	}

	for _, opt := range opts {
		opt(p)
	}

	if len(p.identityProviders) != 0 {
		if p.loginPageURI == nil {
			panic("oauth: login page uri is required for identity providers")
		}
		if p.loginRedirectURI == "" {
			panic("oauth: login redirect uri is required for identity providers")
		}
	}

	return p
}

// Supports checks whether the given grant type has been registered.
func (p *Provider) Supports(grant GrantType) bool {
	_, ok := p.grants[grant]
	return ok
}

// BasePath is the common prefix for all OAuth 2.0 endpoints.
const BasePath = "/oauth"

// Path constants define the specific endpoints managed by the [Provider].
const (
	PathAuthorize           = BasePath + "/authorize"
	PathToken               = BasePath + "/token"
	PathRevoke              = BasePath + "/revoke"
	PathDeviceAuthorization = BasePath + "/device_authorization"
	PathLogin               = BasePath + "/login"
	PathLogout              = BasePath + "/logout"
	PathIntrospect          = BasePath + "/introspect"
	PathWellKnown           = BasePath + "/.well-known/oauth-authorization-server"
	PathKeySet              = BasePath + "/jwks.json"
	PathExternalLogin       = BasePath + "/login/{provider}"
	PathExternalCallback    = BasePath + "/callback/{provider}"
)

// Mount registers the OAuth 2.0 endpoints onto the provided router.
//
// Note: All desired grant types must be registered via [Provider.Register]
// before calling this method.
func (p *Provider) Mount(r *router.Router) {
	r.HandleFunc("GET "+PathAuthorize, p.Authorize)
	r.HandleFunc("POST "+PathAuthorize, p.Authorize)
	r.HandleFunc("POST "+PathToken, p.Token)
	r.HandleFunc("POST "+PathRevoke, p.Revoke)

	if p.verificationURI != "" && p.Supports(GrantTypeDeviceCode) {
		r.HandleFunc("POST "+PathDeviceAuthorization, p.DeviceAuthorization)
	}

	if p.verifier != nil {
		r.HandleFunc("POST "+PathIntrospect, p.Introspect)
	}

	r.HandleFunc("POST "+PathLogin, p.Login)
	r.HandleFunc("POST "+PathLogout, p.Logout)

	if len(p.identityProviders) != 0 {
		r.HandleFunc("GET "+PathExternalLogin, p.ExternalLogin)
		r.HandleFunc("GET "+PathExternalCallback, p.ExternalCallback)
	}

	if p.issuer != "" {
		r.HandleFunc("GET "+PathWellKnown, p.WellKnown)
		r.HandleFunc("GET "+PathKeySet, p.JWKS)
	}
}

// WellKnown handles the OAuth 2.0 Authorization Server Metadata endpoint
// (RFC 8414) for endpoint discovery.
//
// Note: This endpoint is only enabled if a valid URL issuer was specified by
// the configured JWT signer.
//
// The returned metadata dynamically includes endpoints for token revocation,
// introspection, and device authorization only if the provider is correctly
// configured or the respective grants are registered.
func (p *Provider) WellKnown(e *router.Exchange) error {
	if p.issuer == "" {
		e.Status(http.StatusNotFound)
		return nil
	}

	types := make([]string, 0, len(p.grants))
	for grant := range p.grants {
		types = append(types, string(grant))
	}

	res := AuthorizationServerMetadata{
		Issuer:                      p.issuer,
		AuthorizationEndpoint:       p.issuer + PathAuthorize,
		TokenEndpoint:               p.issuer + PathToken,
		KeySetURI:                   p.issuer + PathKeySet,
		RevocationEndpoint:          p.issuer + PathRevoke,
		IntrospectionEndpoint:       p.issuer + PathIntrospect,
		DeviceAuthorizationEndpoint: p.issuer + PathDeviceAuthorization,
		GrantTypesSupported:         types,
		ResponseTypesSupported:      []string{"code"},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post", "none",
		},
	}

	e.SetHeader("Cache-Control", "public, max-age=3600")
	return e.JSON(http.StatusOK, res)
}

// JWKS handles the JSON Web Key Set endpoint (RFC 7517).
//
// It exposes the public keys used by the authorization server to sign tokens,
// allowing external resource servers and clients to verify signatures.
//
// Note: This endpoint is only enabled if a valid URL issuer was specified by
// the configured JWT signer.
func (p *Provider) JWKS(e *router.Exchange) error {
	raw, err := jwk.WriteSet(p.signer.KeySet())
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to marshal JWKS",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate jwks",
		}
	}

	e.SetHeader("Content-Type", "application/jwk-set+json")
	e.SetHeader("Cache-Control", "public, max-age=3600")
	e.Status(http.StatusOK)
	_, err = e.W.Write(raw)
	return err
}

// Authorize handles requests to the authorization endpoint (RFC 6749
// Section 3.1).
//
// It supports both GET and POST requests. The handler validates the client
// identity, redirect URI, and requested scopes. If the resource owner
// has an active session (previously established via [Provider.Login]), it
// generates an authorization code and redirects the user-agent back to
// the client's redirect URI.
func (p *Provider) Authorize(e *router.Exchange) error {
	return wrap(e, p.authorize)
}

// authorize contains the logic for the authorization endpoint.
func (p *Provider) authorize(e *router.Exchange) error {
	data := e.Query()

	clientID := data.Get("client_id")
	if clientID == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing client id",
		}
	}

	client, err := p.clients.GetClient(e.Context(), clientID)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve client",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve client",
		}
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
	if !client.VerifyRedirectURI(redirectURI) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "invalid redirect uri",
		}
	}

	responseType := data.Get("response_type")
	scope := data.Get("scope")
	state := data.Get("state")
	codeChallenge := data.Get("code_challenge")
	codeChallengeMethod := data.Get("code_challenge_method")

	fail := func(code, desc string) error {
		body := url.Values{}
		body.Set("error", code)
		body.Set("error_description", desc)
		// RFC 6749 Section 4.1.2.1: The state parameter is REQUIRED if it
		// was present in the client authorization request.
		if state != "" {
			body.Set("state", state)
		}
		return e.RedirectTo(redirectURI, body, http.StatusFound)
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
	case scope != "" && !client.CanUseScope(scope):
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
	cookie, err := e.Cookie(p.sessionCookieName)
	if err != nil || cookie.Value == "" {
		return fail(
			ErrorCodeAccessDenied,
			"session cookie not found or empty",
		)
	}

	key := cookie.Value
	sub, err := p.subjects.GetSubjectBySession(e.Context(), key)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to lookup subject by session",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to lookup subject",
		}
	}

	if sub == nil {
		return fail(
			ErrorCodeAccessDenied,
			"unknown subject",
		)
	}

	code, err := p.generateOpaqueToken()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate authorization code",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate authorization code",
		}
	}

	if err := p.sessions.CreateAuthCode(
		e.Context(),
		AuthCode{
			Code:                code,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			SubjectID:           sub.ID(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Lifetime:            p.authCodeLifetime,
		},
	); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to store authorization code",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to store authorization code",
		}
	}

	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}

	return e.RedirectTo(redirectURI, params, http.StatusFound)
}

// Token handles requests to the token endpoint (RFC 6749 Section 3.2).
//
// It authenticates the requesting client (via HTTP Basic or POST parameters)
// and processes the specified grant type using the [Grant] implementations
// previously registered via [WithGrant]. Returns a JSON response containing an
// access token and optional refresh token.
func (p *Provider) Token(e *router.Exchange) error {
	return wrap(e, p.token)
}

// token contains the logic for the token endpoint.
func (p *Provider) token(e *router.Exchange) error {
	pro, err := p.authenticate(e)
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

	if !pro.Client.CanUseGrant(grantType) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "grant type not allowed",
		}
	}

	grant, ok := p.grants[grantType]
	if !ok {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeUnsupportedGrantType,
			Description: "unsupported grant type",
		}
	}

	iss, err := grant.Authorize(e.Context(), pro)
	if err != nil {
		return err
	}

	clientID := pro.Client.ID()

	claims := &auth.Claims{
		Scope: strings.Fields(iss.Scope),
		Azp:   clientID,
	}

	// Populate claims based on the context of the grant.
	if iss.Subject == "" {
		claims.Sub = clientID // The subject is the client itself
	} else if sub, err := p.subjects.GetSubject(
		e.Context(),
		iss.Subject,
	); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve subject for claims",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve subject",
		}
	} else if sub != nil {
		claims.Sub = sub.ID()
		claims.Roles = sub.Roles()
	} else {
		p.logger.ErrorContext(
			e.Context(),
			"Subject not found for claims",
			slog.String("subject", iss.Subject),
		)

		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "subject no longer available",
		}
	}

	token, err := p.signer.Sign(claims)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to sign access token",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to mint access token",
		}
	}

	res := TokenResponse{
		AccessToken: string(token),
		TokenType:   auth.Scheme,
		ExpiresIn:   int(p.accessTokenLifetime.Seconds()),
		Scope:       iss.Scope,
	}

	if iss.Refreshable {
		token, err := p.generateOpaqueToken()
		if err != nil {
			p.logger.ErrorContext(
				e.Context(),
				"Failed to generate refresh token",
				slog.Any("error", err),
			)

			return &Error{
				Status:      http.StatusInternalServerError,
				Code:        ErrorCodeServerError,
				Description: "failed to generate refresh token",
			}
		}

		err = p.sessions.CreateRefreshToken(e.Context(), RefreshToken{
			Token:     token,
			ClientID:  pro.Client.ID(),
			SubjectID: iss.Subject,
			Scope:     iss.Scope,
			Lifetime:  p.refreshTokenLifetime,
		})
		if err != nil {
			p.logger.ErrorContext(
				e.Context(),
				"Failed to save refresh token",
				slog.Any("error", err),
			)

			return &Error{
				Status:      http.StatusInternalServerError,
				Code:        ErrorCodeServerError,
				Description: "failed to save refresh token",
			}
		}

		res.RefreshToken = token
	}

	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")
	return e.JSON(http.StatusOK, res)
}

func (p *Provider) authenticate(e *router.Exchange) (*Proposal, error) {
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
	} else if data.Has("client_id") || data.Has("client_secret") {
		// RFC 6749 Section 2.3.1: MUST NOT use more than one auth method.
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "multiple client authentication methods used",
		}
	}

	if clientID == "" {
		p.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "missing client id",
		}
	}

	client, err := p.clients.GetClient(e.Context(), clientID)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Client lookup failed",
			slog.Any("error", err),
		)

		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve client",
		}
	}

	if client == nil {
		p.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "unknown client",
		}
	}

	if clientSecret == "" && !client.Public() {
		p.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "client requires a secret",
		}
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		p.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "invalid client secret",
		}
	}

	return &Proposal{
		Client:   client,
		Sessions: p.sessions,
		Logger:   p.logger,
		data:     data,
	}, nil
}

// challenge sets the WWW-Authenticate header to signal to the client that
// HTTP Basic authentication is required, as mandated by RFC 6749 Section 5.2
// for client authentication failures.
func (p *Provider) challenge(e *router.Exchange) {
	e.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", p.realm))
}

// Revoke handles token revocation requests per RFC 7009.
//
// It allows clients to signal that a previously obtained refresh token is no
// longer needed. The handler authenticates the client and, if the provided
// token is a valid refresh token belonging to that client, removes it from the
// [SessionStore].
func (p *Provider) Revoke(e *router.Exchange) error {
	return wrap(e, p.revoke)
}

// revoke contains the logic for token revocation.
func (p *Provider) revoke(e *router.Exchange) error {
	pro, err := p.authenticate(e)
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
	r, err := p.sessions.GetRefreshToken(e.Context(), token)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve refresh token during revocation",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve token",
		}
	}
	if r.Token == "" || r.ClientID != pro.Client.ID() {
		// Token not found or belongs to another client. Return 200 OK.
		e.Status(http.StatusOK)
		return nil
	}

	if err := p.sessions.DeleteRefreshToken(e.Context(), token); err != nil {
		p.logger.ErrorContext(
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
// provided during provider initialization.
func (p *Provider) DeviceAuthorization(e *router.Exchange) error {
	return wrap(e, p.deviceAuthorization)
}

// deviceAuthorization contains the logic for device authorization requests.
func (p *Provider) deviceAuthorization(e *router.Exchange) error {
	pro, err := p.authenticate(e)
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

	if p.verificationURI == "" {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "device authorization is not configured",
		}
	}

	deviceCode, err := p.generateOpaqueToken()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate device code",
			slog.Any("error", err),
		)
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate device code",
		}
	}

	userCode, err := p.generateUserCode()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate user code",
			slog.Any("error", err),
		)
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate user code",
		}
	}

	scope := pro.Get("scope")
	if scope != "" && !pro.Client.CanUseScope(scope) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	expiresAt := time.Now().Add(p.deviceCodeLifetime)

	if err := p.sessions.CreateDeviceCode(e.Context(), DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   pro.Client.ID(),
		Scope:      scope,
		Status:     "pending",
		ExpiresAt:  expiresAt,
	}); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to store device code",
			slog.Any("error", err),
		)
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to store device code",
		}
	}

	res := DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: p.verificationURI,
		ExpiresIn:       int(p.deviceCodeLifetime.Seconds()),
		Interval:        5,
	}

	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")
	return e.JSON(http.StatusOK, res)
}

// Login handles the resource owner authentication and establishes a session.
//
// It expects a JSON payload with username and password. On success, it
// generates a high-entropy session key, stores it via [SubjectStore], and sets
// a secure session cookie on the user-agent.
//
// Note: When calling this endpoint from a cross-origin frontend (e.g., an SPA),
// the CORS middleware must be configured with AllowCredentials set to true,
// and AllowOrigin must not be a wildcard ("*").
func (p *Provider) Login(e *router.Exchange) error {
	var cred LoginRequest
	if err := e.BindJSON(&cred); err != nil {
		return err
	}

	sub, err := p.subjects.Authenticate(
		e.Context(),
		cred.Username,
		cred.Password,
	)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Subject authentication lookup failed",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to lookup subject",
		}
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      router.ReasonValidationFailed,
			Description: "invalid credentials",
		}
	}

	key, err := p.generateOpaqueToken()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate session key",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to generate session key",
		}
	}

	if err := p.subjects.CreateSession(e.Context(), key, sub.ID()); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to create subject session",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to create subject session",
		}
	}

	e.SetCookie(&http.Cookie{
		Name:     p.sessionCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	e.NoContent()
	return nil
}

// Logout terminates the resource owner's session.
//
// It identifies the session via the session cookie, deletes the mapping from
// the [SubjectStore], and clears the cookie on the user-agent by setting a
// negative Max-Age value.
func (p *Provider) Logout(e *router.Exchange) error {
	cookie, err := e.Cookie(p.sessionCookieName)
	if err == nil && cookie.Value != "" {
		if err := p.subjects.DeleteSession(e.Context(), cookie.Value); err != nil {
			p.logger.ErrorContext(
				e.Context(),
				"Failed to delete subject session",
				slog.Any("error", err),
			)
		}
	}

	// Instruct the browser to wipe all local state (cookies, storage, cache).
	// Note: The double-quotes around the asterisk are required by the spec.
	e.SetHeader("Clear-Site-Data", `"*"`)

	e.SetCookie(&http.Cookie{
		Name:     p.sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	e.NoContent()
	return nil
}

// ExternalLogin initiates a social authentication flow by redirecting the
// resource owner to the requested external identity provider.
func (p *Provider) ExternalLogin(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := p.identityProviders[name]
	if !ok {
		e.Status(http.StatusNotFound)
		return nil
	}

	state, err := p.generateOpaqueToken()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate state",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to generate state",
		}
	}

	e.SetCookie(&http.Cookie{
		Name:     p.stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	authURL, err := idp.AuthURL(e.Context(), state)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate auth url",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to initiate external login",
		}
	}

	e.SetHeader("Location", authURL)
	e.Status(http.StatusFound)
	return nil
}

// ExternalCallback handles the redirect from an external identity provider,
// verifies the state, exchanges credentials for an external identity, and
// establishes a local session.
func (p *Provider) ExternalCallback(e *router.Exchange) error {
	err := p.externalCallback(e)
	if v, ok := errors.AsType[*router.Error](err); ok {
		u := *p.loginPageURI
		q := u.Query()
		params := v.Query()
		for key := range params {
			q.Set(key, params.Get(key))
		}
		u.RawQuery = q.Encode()

		e.SetHeader("Location", u.String())
		e.Status(http.StatusFound)
		return nil
	}
	return err
}

func (p *Provider) externalCallback(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := p.identityProviders[name]
	if !ok {
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      router.ReasonValidationFailed,
			Description: "unknown identity provider",
		}
	}

	cookie, err := e.Cookie(p.stateCookieName)
	if err != nil || cookie.Value == "" {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "missing or expired state cookie",
		}
	}

	// Clear the state cookie immediately to prevent replay attacks.
	e.SetCookie(&http.Cookie{
		Name:     p.stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	queryState := e.Query().Get("state")
	if queryState != cookie.Value {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "state mismatch",
		}
	}

	identity, err := idp.Process(e.Context(), e.R)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"External exchange failed",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "failed to exchange external credentials",
		}
	}

	sub, err := p.subjects.GetSubjectByExternalID(
		e.Context(),
		name,
		identity,
	)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"External subject lookup failed",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonValidationFailed,
			Description: "failed to lookup subject",
		}
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "external identity is not linked to any local subject",
		}
	}

	key, err := p.generateOpaqueToken()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate session key",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to generate session key",
		}
	}

	if err := p.subjects.CreateSession(e.Context(), key, sub.ID()); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to create subject session",
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to create subject session",
		}
	}

	e.SetCookie(&http.Cookie{
		Name:     p.sessionCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	e.SetHeader("Location", p.loginRedirectURI)
	e.Status(http.StatusFound)
	return nil
}

// Introspect handles token introspection requests (RFC 7662).
//
// It allows authorized resource servers to query the metadata and active status
// of a given access token. The handler authenticates the client making the
// request and uses the configured [jwt.Verifier] to check the provided token's
// validity.
func (p *Provider) Introspect(e *router.Exchange) error {
	// Exit if token verification is not supported.
	if p.verifier == nil {
		e.Status(http.StatusNotFound)
		return nil
	}

	return wrap(e, p.introspect)
}

// introspect contains the logic for the token introspection endpoint.
func (p *Provider) introspect(e *router.Exchange) error {
	pro, err := p.authenticate(e)
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

	var res IntrospectionResponse

	if claims, err := p.verifier.Verify([]byte(token)); err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Token verification failed during introspection",
			slog.Any("error", err),
		)
	} else {
		res = IntrospectionResponse{
			Active:   true,
			ClientID: pro.Client.ID(),
			Scope:    claims.Scope.String(),
			Jti:      claims.Jti,
			Iss:      claims.Iss,
			Aud:      claims.Aud,
			Sub:      claims.Sub,
			Iat:      claims.Iat,
			Exp:      claims.Exp,
			Nbf:      claims.Nbf,
		}
	}

	return e.JSON(http.StatusOK, res)
}

// wrap executes the handler and translates any returned [Error] into an HTTP
// JSON response using the error's defined status code.
func wrap(e *router.Exchange, handler func(*router.Exchange) error) error {
	err := handler(e)
	if v, ok := errors.AsType[*Error](err); ok {
		return e.JSON(v.Status, v)
	}
	return err
}
