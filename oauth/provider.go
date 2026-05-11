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
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

const (
	// DefaultSessionCookieName is the default name for the cookie used to
	// track the resource owner's session.
	DefaultSessionCookieName = "oauth_session"
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
	// VerificationURI is the endpoint where users authorize device codes.
	// Required if using the Device Authorization Grant.
	VerificationURI string
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
	logger               *slog.Logger
	sessionCookieName    string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	authCodeLifetime     time.Duration
	realm                string
	deviceCodeLifetime   time.Duration
	verificationURI      string
	issuer               string
}

// NewProvider creates a new Provider with the specified configuration.
//
// It panics if any mandatory options are missing.
func NewProvider(cfg Config) *Provider {
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

	accessTokenLifetime := cfg.AccessTokenLifetime
	if accessTokenLifetime == 0 {
		accessTokenLifetime = DefaultAccessTokenLifetime
	}

	refreshTokenLifetime := cfg.RefreshTokenLifetime
	if refreshTokenLifetime == 0 {
		refreshTokenLifetime = DefaultRefreshTokenLifetime
	}

	authCodeLifetime := cfg.AuthCodeLifetime
	if authCodeLifetime == 0 {
		authCodeLifetime = DefaultAuthCodeLifetime
	}

	realm := cfg.Realm
	if realm == "" {
		realm = DefaultRealm
	}

	deviceCodeLifetime := cfg.DeviceCodeLifetime
	if deviceCodeLifetime == 0 {
		deviceCodeLifetime = DefaultDeviceCodeLifetime
	}

	issuer := ""
	if iss := strings.TrimRight(cfg.Signer.Issuer(), "/"); iss != "" {
		if u, err := url.Parse(iss); err == nil {
			if u.Scheme != "" && u.Host != "" {
				issuer = iss
			}
		}
	}

	return &Provider{
		signer:               cfg.Signer,
		verifier:             cfg.Verifier,
		clients:              cfg.Clients,
		sessions:             cfg.Sessions,
		subjects:             cfg.Subjects,
		grants:               make(map[GrantType]Grant),
		logger:               logger,
		sessionCookieName:    sessionCookieName,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		authCodeLifetime:     authCodeLifetime,
		realm:                realm,
		deviceCodeLifetime:   deviceCodeLifetime,
		verificationURI:      cfg.VerificationURI,
		issuer:               issuer,
	}
}

// Register adds a new grant type handler to the provider.
// It returns the [Provider] pointer to allow for method chaining.
func (p *Provider) Register(grant Grant) *Provider {
	p.grants[grant.Type()] = grant
	return p
}

// Supports checks whether the given grant type has been registered.
func (p *Provider) Supports(grant GrantType) bool {
	_, ok := p.grants[grant]
	return ok
}

const (
	pathAuthorize           = "/authorize"
	pathToken               = "/token"
	pathRevoke              = "/revoke"
	pathDeviceAuthorization = "/device_authorization"
	pathLogin               = "/login"
	pathLogout              = "/logout"
	pathIntrospect          = "/introspect"
	pathWellKnown           = "/.well-known/oauth-authorization-server"
)

// Mount registers the OAuth 2.0 endpoints onto the provided router.
//
// Note: All desired grant types must be registered via [Provider.Register]
// before calling this method.
func (p *Provider) Mount(r *router.Router) {
	r.HandleFunc("GET "+pathAuthorize, p.Authorize)
	r.HandleFunc("POST "+pathAuthorize, p.Authorize)
	r.HandleFunc("POST "+pathToken, p.Token)
	r.HandleFunc("POST "+pathRevoke, p.Revoke)

	if p.verificationURI != "" && p.Supports(GrantTypeDeviceCode) {
		r.HandleFunc("POST "+pathDeviceAuthorization, p.DeviceAuthorization)
	}

	if p.verifier != nil {
		r.HandleFunc("POST "+pathIntrospect, p.Introspect)
	}

	r.HandleFunc("POST "+pathLogin, p.Login)
	r.HandleFunc("POST "+pathLogout, p.Logout)

	if p.issuer != "" {
		r.HandleFunc("GET "+pathWellKnown, p.WellKnown)
	}
}

// WellKnown handles the OAuth 2.0 Authorization Server Metadata endpoint
// (RFC 8414) for endpoint discovery.
//
// Note: This endpoint is only enabled if a valid URL issuer was specified by
// the configured JWT signer.
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
		AuthorizationEndpoint:       p.issuer + pathAuthorize,
		TokenEndpoint:               p.issuer + pathToken,
		RevocationEndpoint:          p.issuer + pathRevoke,
		IntrospectionEndpoint:       p.issuer + pathIntrospect,
		DeviceAuthorizationEndpoint: p.issuer + pathDeviceAuthorization,
		GrantTypesSupported:         types,
		ResponseTypesSupported:      []string{"code"},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post", "none",
		},
	}

	e.SetHeader("Cache-Control", "public, max-age=3600")
	return e.JSON(http.StatusOK, res)
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
			Description: "missing client ID",
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
			Description: "missing redirect URI",
		}
	}
	if !client.VerifyRedirectURI(redirectURI) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "invalid redirect URI",
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

	code, err := opaque()
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
// and processes the specified grant_type. Supported flows depend on which
// [Grant] implementations have been registered with [Provider.Register].
// Returns a JSON response containing an access token and optional refresh token.
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
		token, err := opaque()
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

	deviceCode, err := opaque()
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

	userCode, err := userCode()
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
	return wrap(e, p.login)
}

// login contains the logic for resource owner authentication.
func (p *Provider) login(e *router.Exchange) error {
	var req LoginRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	username := req.Username
	if username == "" {
		return &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeAccessDenied,
			Description: "missing username",
		}
	}

	password := req.Password
	if password == "" {
		return &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeAccessDenied,
			Description: "missing password",
		}
	}

	sub, err := p.subjects.Authenticate(
		e.Context(),
		username,
		password,
	)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Subject authentication lookup failed",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to lookup subject",
		}
	}
	if sub == nil {
		return &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeAccessDenied,
			Description: "invalid credentials",
		}
	}

	key, err := opaque()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate session key",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate session key",
		}
	}

	if err := p.subjects.CreateSession(e.Context(), key, sub.ID()); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to create subject session",
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to create subject session",
		}
	}

	e.SetCookie(p.cookie(key))
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

	e.SetCookie(p.cookie(""))
	e.NoContent()
	return nil
}

// cookie constructs an [http.Cookie] for the resource owner session.
//
// If the provided key is empty, it returns a cookie with a negative Max-Age
// to signal the user-agent to delete it. Otherwise, it creates a secure,
// HTTP-only cookie with the session key.
func (p *Provider) cookie(key string) *http.Cookie {
	c := &http.Cookie{
		Name:     p.sessionCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if key == "" {
		c.MaxAge = -1
	}
	return c
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
