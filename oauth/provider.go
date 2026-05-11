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
	DefaultSessionCookieName    = "session"
	DefaultAccessTokenLifetime  = 5 * time.Minute
	DefaultRefreshTokenLifetime = 7 * 24 * time.Hour
	DefaultAuthCodeLifetime     = 10 * time.Minute
)

// Config holds the configuration options for an OAuth 2.0 Provider.
type Config struct {
	Signer               jwt.Signer
	Verifier             jwt.Verifier[*auth.Claims]
	Clients              ClientStore
	Sessions             SessionStore
	Subjects             SubjectStore
	Logger               *slog.Logger
	SessionCookieName    string
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	AuthCodeLifetime     time.Duration
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
}

// NewProvider creates a new Provider with the specified configuration.
func NewProvider(cfg Config) *Provider {
	if cfg.Signer == nil {
		panic("oauth: signer is required")
	}

	if cfg.Verifier == nil {
		panic("oauth: verifier is required")
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

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Provider{
		signer:               cfg.Signer,
		clients:              cfg.Clients,
		sessions:             cfg.Sessions,
		subjects:             cfg.Subjects,
		grants:               make(map[GrantType]Grant),
		logger:               logger,
		sessionCookieName:    sessionCookieName,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		authCodeLifetime:     authCodeLifetime,
	}
}

// Register adds a new grant type handler to the provider.
func (p *Provider) Register(grant Grant) { p.grants[grant.Type()] = grant }

// Mount registers the OAuth 2.0 endpoints onto the provided router.
func (p *Provider) Mount(r *router.Router) {
	r.HandleFunc("GET /authorize", p.Authorize)
	r.HandleFunc("POST /authorize", p.Authorize)
	r.HandleFunc("POST /token", p.Token)
	r.HandleFunc("POST /revoke", p.Revoke)
	r.HandleFunc("POST /login", p.Login)
	r.HandleFunc("POST /logout", p.Logout)
	r.HandleFunc("POST /introspect", p.Introspect)
}

// Authorize handles the authorization endpoint requests.
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
			"client is not authorized to use authorization code grant",
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

// Token handles the token endpoint requests.
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
			Description: "subject not found",
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
	}

	if clientID == "" {
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
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
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "unknown client",
		}
	}

	if clientSecret == "" && !client.Public() {
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "client requires a secret",
		}
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
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

// Revoke handles token revocation requests.
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

// Login handles the resource owner authentication and establishes a session.
func (p *Provider) Login(e *router.Exchange) error {
	return wrap(e, p.login)
}

// login contains the logic for resource owner authentication.
func (p *Provider) login(e *router.Exchange) error {
	var req LoginRequest
	if err := e.BindJSON(&req); err != nil {
		return err
	}

	sub, err := p.subjects.Authenticate(
		e.Context(),
		req.Username,
		req.Password,
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

	e.SetCookie(p.cookie(""))
	e.NoContent()
	return nil
}

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

// Introspect handles the token introspection endpoint requests.
func (p *Provider) Introspect(e *router.Exchange) error {
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

// wrap executes the handler and translates any returned [*Error] into an HTTP
// JSON response using the error's defined status code.
func wrap(e *router.Exchange, handler func(*router.Exchange) error) error {
	err := handler(e)
	if v, ok := errors.AsType[*Error](err); ok {
		return e.JSON(v.Status, v)
	}
	return err
}
