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
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/internal/pkce"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

const (
	DefaultAuthCodeLifetime     = 5 * time.Minute
	DefaultAccessTokenLifetime  = 1 * time.Hour
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour
	DefaultSessionCookieName    = "session"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

const (
	ParamClientID            = "client_id"
	ParamClientSecret        = "client_secret"
	ParamCode                = "code"
	ParamCodeChallenge       = "code_challenge"
	ParamCodeChallengeMethod = "code_challenge_method"
	ParamCodeVerifier        = "code_verifier"
	ParamGrantType           = "grant_type"
	ParamRedirectURI         = "redirect_uri"
	ParamRefreshToken        = "refresh_token"
	ParamResponseType        = "response_type"
	ParamScope               = "scope"
	ParamState               = "state"
	ParamToken               = "token"
)

// Client represents an OAuth 2.0 registered client application.
type Client interface {
	// ID returns the unique identifier for the client.
	ID() string
	// IsPublic indicates if the client is capable of keeping a secret (e.g.,
	// false for SPAs).
	IsPublic() bool
	// VerifySecret checks if the provided secret matches the client's registered
	// secret.
	VerifySecret(secret string) bool
	// VerifyRedirectURI checks if the given URI is an allowed redirect
	// destination.
	VerifyRedirectURI(uri string) bool
	// CanUseGrant checks if the client is authorized to use the specified
	// grant type.
	CanUseGrant(grant string) bool
	// CanUseScope checks if the client is allowed to request the specified scope.
	CanUseScope(scope string) bool
}

// ClientStore provides data access for registered OAuth 2.0 clients.
type ClientStore interface {
	// GetClient retrieves a client by its unique ID.
	GetClient(ctx context.Context, id string) (Client, error)
}

// User represents an authenticated resource owner.
type User interface {
	// ID returns the unique identifier for the user.
	ID() string
	// Roles returns the assigned roles for the user.
	Roles() []string
}

// UserStore provides data access and authentication for resource owners.
type UserStore interface {
	// GetUser retrieves a user by their unique ID.
	GetUser(ctx context.Context, id string) (User, error)
	// GetUserBySession retrieves the authenticated user via their session key.
	// This is required for the authorization endpoint.
	GetUserBySession(ctx context.Context, key string) (User, error)
}

// AuthCode holds the state bound to an authorization code.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	Lifetime            time.Duration
}

// RefreshToken holds the state bound to a refresh token.
type RefreshToken struct {
	Token    string
	ClientID string
	UserID   string
	Scope    string
	Lifetime time.Duration
}

// SessionStore abstracts the persistence layer for ephemeral OAuth 2.0
// artifacts.
type SessionStore interface {
	AddAuthCode(ctx context.Context, data AuthCode) error
	GetAuthCode(ctx context.Context, code string) (AuthCode, error)
	DelAuthCode(ctx context.Context, code string) error
	AddRefreshToken(ctx context.Context, data RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (RefreshToken, error)
	DelRefreshToken(ctx context.Context, token string) error
}

// Config contains all necessary dependencies and settings for the OAuth 2.0
// Provider.
type Config struct {
	// Signer is used to mint new access tokens (JWTs).
	Signer jwt.Signer
	// Verifier is used to validate access tokens during introspection.
	Verifier jwt.Verifier[*auth.Claims]

	ClientStore  ClientStore
	UserStore    UserStore
	SessionStore SessionStore

	// AuthCodeLifetime defines how long an authorization code is valid.
	// Defaults to [DefaultAuthCodeLifetime].
	AuthCodeLifetime time.Duration
	// AccessTokenLifetime defines the lifespan of issued access tokens.
	// Defaults to [DefaultAccessTokenLifetime].
	AccessTokenLifetime time.Duration
	// RefreshTokenLifetime defines the lifespan of refresh tokens.
	// Defaults to [DefaultRefreshTokenLifetime].
	RefreshTokenLifetime time.Duration
	// SessionCookieName defines the name of the cookie holding the user's
	// session key. Defaults to [DefaultSessionCookieName].
	SessionCookieName string

	// Logger is used for structured logging. Defaults to slog.Default().
	Logger *slog.Logger
}

// Provider is the default implementation of the OAuth 2.0 HTTP endpoints.
type Provider struct {
	signer               jwt.Signer
	verifier             jwt.Verifier[*auth.Claims]
	clientStore          ClientStore
	userStore            UserStore
	sessionStore         SessionStore
	authCodeLifetime     time.Duration
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	sessionCookieName    string
	logger               *slog.Logger
}

// NewProvider creates a new OAuth 2.0 provider with the specified configuration.
func NewProvider(cfg Config) *Provider {
	if cfg.Signer == nil {
		panic("oauth: signer is required")
	}
	if cfg.Verifier == nil {
		panic("oauth: verifier is required")
	}
	if cfg.ClientStore == nil {
		panic("oauth: client store is required")
	}
	if cfg.UserStore == nil {
		panic("oauth: user store is required")
	}
	if cfg.SessionStore == nil {
		panic("oauth: session store is required")
	}
	if cfg.AuthCodeLifetime == 0 {
		cfg.AuthCodeLifetime = DefaultAuthCodeLifetime
	}
	if cfg.AccessTokenLifetime == 0 {
		cfg.AccessTokenLifetime = DefaultAccessTokenLifetime
	}
	if cfg.RefreshTokenLifetime == 0 {
		cfg.RefreshTokenLifetime = DefaultRefreshTokenLifetime
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = DefaultSessionCookieName
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Provider{
		signer:               cfg.Signer,
		verifier:             cfg.Verifier,
		clientStore:          cfg.ClientStore,
		userStore:            cfg.UserStore,
		sessionStore:         cfg.SessionStore,
		authCodeLifetime:     cfg.AuthCodeLifetime,
		accessTokenLifetime:  cfg.AccessTokenLifetime,
		refreshTokenLifetime: cfg.RefreshTokenLifetime,
		sessionCookieName:    cfg.SessionCookieName,
		logger:               cfg.Logger,
	}
}

// Mount registers the OAuth 2.0 endpoints onto the provided router.
func (p *Provider) Mount(r *router.Router) {
	r.HandleFunc("GET /authorize", p.Authorize)
	r.HandleFunc("POST /authorize", p.Authorize)
	r.HandleFunc("POST /token", p.Token)
	r.HandleFunc("POST /introspect", p.Introspect)
	r.HandleFunc("POST /revoke", p.Revoke)
}

// Error returns an OAuth 2.0 compliant error response as JSON.
type Error struct {
	Reason      string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Error implements the standard error interface.
func (e Error) Error() string {
	if e.Description != "" {
		return e.Reason + ": " + e.Description
	}
	return e.Reason
}

func (e Error) Params() url.Values {
	params := url.Values{}
	params.Set("error", e.Reason)
	if e.Description != "" {
		params.Set("error_description", e.Description)
	}
	return params
}

const (
	ReasonAccessDenied            = "access_denied"
	ReasonCodeInvalidRequest      = "invalid_request"
	ReasonInvalidClient           = "invalid_client"
	ReasonInvalidGrant            = "invalid_grant"
	ReasonInvalidScope            = "invalid_scope"
	ReasonServerError             = "server_error"
	ReasonUnauthorizedClient      = "unauthorized_client"
	ReasonUnsupportedGrantType    = "unsupported_grant_type"
	ReasonUnsupportedResponseType = "unsupported_response_type"
)

var (
	errAccessDenied                   = Error{Reason: ReasonAccessDenied, Description: "user authentication required"}
	errClientAuthFailed               = Error{Reason: ReasonInvalidClient, Description: "client authentication failed"}
	errClientMismatch                 = Error{Reason: ReasonInvalidGrant, Description: "client mismatch"}
	errClientNotFound                 = Error{Reason: ReasonInvalidClient, Description: "client not found"}
	errGrantNotAllowed                = Error{Reason: ReasonUnauthorizedClient, Description: "grant type not allowed for client"}
	errInvalidAuthCode                = Error{Reason: ReasonInvalidGrant, Description: "invalid or expired authorization code"}
	errInvalidFormBody                = Error{Reason: ReasonCodeInvalidRequest, Description: "invalid form body"}
	errInvalidRedirectURI             = Error{Reason: ReasonCodeInvalidRequest, Description: "invalid redirect_uri"}
	errInvalidRefreshToken            = Error{Reason: ReasonInvalidGrant, Description: "invalid or expired refresh token"}
	errMissingClientID                = Error{Reason: ReasonCodeInvalidRequest, Description: "missing client_id"}
	errMissingCode                    = Error{Reason: ReasonCodeInvalidRequest, Description: "missing code"}
	errMissingCodeChallenge           = Error{Reason: ReasonCodeInvalidRequest, Description: "code_challenge is required (PKCE)"}
	errMissingCodeVerifier            = Error{Reason: ReasonCodeInvalidRequest, Description: "missing code_verifier"}
	errMissingRedirectURI             = Error{Reason: ReasonCodeInvalidRequest, Description: "missing redirect_uri"}
	errMissingRefreshToken            = Error{Reason: ReasonCodeInvalidRequest, Description: "missing refresh_token"}
	errMissingToken                   = Error{Reason: ReasonCodeInvalidRequest, Description: "missing token"}
	errPKCEVerificationFailed         = Error{Reason: ReasonInvalidGrant, Description: "PKCE verification failed"}
	errRedirectURIMismatch            = Error{Reason: ReasonInvalidGrant, Description: "redirect_uri mismatch"}
	errScopeNotAllowed                = Error{Reason: ReasonInvalidScope, Description: "requested scope is not allowed"}
	errServerError                    = Error{Reason: ReasonServerError, Description: "unexpected internal error"}
	errUnauthorizedGrantType          = Error{Reason: ReasonUnauthorizedClient, Description: "client cannot use requested grant type"}
	errUnsupportedCodeChallengeMethod = Error{Reason: ReasonCodeInvalidRequest, Description: "unsupported code_challenge_method"}
	errUnsupportedGrantType           = Error{Reason: ReasonUnsupportedGrantType, Description: "grant type not supported"}
	errUnsupportedResponseType        = Error{Reason: ReasonUnsupportedResponseType, Description: "only code response type is supported"}
)

// TokenResponse outlines the standard payload returned after a successful token
// grant.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IntrospectionResponse outlines the RFC 7662 compliant JSON payload.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	JWTID     string   `json:"jti,omitempty"`
}

// Authorize validates the parameters and redirects the user with an auth
// code.
func (p *Provider) Authorize(e *router.Exchange) error {
	form := e.Query()
	clientID := form.Get(ParamClientID)
	redirectURI := form.Get(ParamRedirectURI)
	responseType := form.Get(ParamResponseType)
	scope := form.Get(ParamScope)
	state := form.Get(ParamState)
	codeChallenge := form.Get(ParamCodeChallenge)
	codeChallengeMethod := form.Get(ParamCodeChallengeMethod)

	if clientID == "" {
		return e.JSON(http.StatusBadRequest, errMissingClientID)
	}

	client, err := p.clientStore.GetClient(e.Context(), clientID)
	if err != nil || client == nil {
		p.logger.DebugContext(
			e.Context(),
			"Client not found",
			slog.String("client_id", clientID),
		)
		return e.JSON(http.StatusUnauthorized, errClientNotFound)
	}

	if redirectURI == "" {
		return e.JSON(http.StatusBadRequest, errMissingRedirectURI)
	}
	if !client.VerifyRedirectURI(redirectURI) {
		return e.JSON(http.StatusBadRequest, errInvalidRedirectURI)
	}

	sendError := func(red Error) error {
		return e.RedirectTo(redirectURI, red.Params(), http.StatusFound)
	}

	switch {
	case responseType != "code":
		return sendError(errUnsupportedResponseType)
	case !client.CanUseGrant(GrantTypeAuthorizationCode):
		return sendError(errUnauthorizedGrantType)
	case codeChallenge == "":
		return sendError(errMissingCodeChallenge)
	case !pkce.Supports(codeChallengeMethod):
		return sendError(errUnsupportedCodeChallengeMethod)
	}

	cookie, err := e.R.Cookie(p.sessionCookieName)
	if err != nil || cookie.Value == "" {
		p.logger.DebugContext(
			e.Context(),
			"Session cookie not found or empty",
			slog.Any("error", err),
		)
		return sendError(errAccessDenied)
	}

	user, err := p.userStore.GetUserBySession(e.Context(), cookie.Value)
	if err != nil || user == nil {
		p.logger.DebugContext(
			e.Context(),
			"User lookup by session failed",
			slog.Any("error", err),
		)
		return sendError(errAccessDenied)
	}

	code, err := opaque()
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate opaque token",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	data := AuthCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		UserID:              user.ID(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Lifetime:            p.authCodeLifetime,
	}

	if err := p.sessionStore.AddAuthCode(
		e.Context(),
		data,
	); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to store authorization code",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	params := url.Values{}
	params.Set(ParamCode, code)
	if state != "" {
		params.Set(ParamState, state)
	}

	return e.RedirectTo(redirectURI, params, http.StatusFound)
}

// Token processes access token requests.
func (p *Provider) Token(e *router.Exchange) error {
	form, client, err := p.authenticateClient(e)
	if err != nil {
		return err
	}

	grant := form.Get(ParamGrantType)
	if !client.CanUseGrant(grant) {
		p.logger.DebugContext(
			e.Context(),
			"Grant type not allowed for client",
			slog.String("grant_type", grant),
		)
		return e.JSON(http.StatusBadRequest, errGrantNotAllowed)
	}

	switch grant {
	case GrantTypeAuthorizationCode:
		return p.handleAuthorizationCodeGrant(e, form, client)
	case GrantTypeClientCredentials:
		return p.handleClientCredentialsGrant(e, form, client)
	case GrantTypeRefreshToken:
		return p.handleRefreshTokenGrant(e, form, client)
	default:
		return e.JSON(http.StatusBadRequest, errUnsupportedGrantType)
	}
}

// Introspect implements RFC 7662 to determine the active state of an
// OAuth 2.0 token.
func (p *Provider) Introspect(e *router.Exchange) error {
	form, _, err := p.authenticateClient(e)
	if err != nil {
		return err
	}

	tok := form.Get(ParamToken)
	if tok == "" {
		return e.JSON(http.StatusBadRequest, errMissingToken)
	}

	// RFC 7662: If the token is invalid, expired, or revoked, the authorization
	// server MUST return an active boolean set to false.
	claims, err := p.verifier.Verify([]byte(tok))
	if err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Token introspection verification failed",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusOK, IntrospectionResponse{Active: false})
	}

	res := IntrospectionResponse{
		Active:   true,
		Scope:    claims.Scp,
		Subject:  claims.Subject(),
		Issuer:   claims.Issuer(),
		Audience: claims.Audience(),
		JWTID:    claims.ID(),
	}
	if t := claims.ExpiresAt(); !t.IsZero() {
		res.ExpiresAt = t.Unix()
	}
	if t := claims.IssuedAt(); !t.IsZero() {
		res.IssuedAt = t.Unix()
	}
	if t := claims.NotBefore(); !t.IsZero() {
		res.NotBefore = t.Unix()
	}

	return e.JSON(http.StatusOK, res)
}

// Revoke implements RFC 7009 to allow clients to invalidate their tokens.
func (p *Provider) Revoke(e *router.Exchange) error {
	form, _, err := p.authenticateClient(e)
	if err != nil {
		return err
	}

	tok := form.Get(ParamToken)
	if tok == "" {
		return e.JSON(http.StatusBadRequest, errMissingToken)
	}

	// Access tokens are stateless JWTs in this implementation, so we primarily
	// care about revoking refresh tokens. RFC 7009 dictates that an invalid
	// or already revoked token should still result in a 200 OK response.
	if err := p.sessionStore.DelRefreshToken(e.Context(), tok); err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Failed to delete refresh token during revocation",
			slog.Any("error", err),
		)
	}

	e.Status(http.StatusOK)
	return nil
}

// authenticateClient reads the form body, logs errors if invalid, and
// authenticates the client.
func (p *Provider) authenticateClient(
	e *router.Exchange,
) (url.Values, Client, error) {
	form, err := e.ReadForm()
	if err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Invalid form body",
			slog.Any("error", err),
		)
		return nil, nil, e.JSON(http.StatusBadRequest, errInvalidFormBody)
	}

	id, secret, ok := e.R.BasicAuth()
	if !ok {
		id = form.Get(ParamClientID)
		secret = form.Get(ParamClientSecret)
	}

	fail := func(msg string) (url.Values, Client, error) {
		p.logger.DebugContext(
			e.Context(),
			msg,
			slog.String("client_id", id),
		)
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return nil, nil, e.JSON(http.StatusUnauthorized, errClientAuthFailed)
	}

	if id == "" {
		return fail("Missing client_id")
	}

	client, err := p.clientStore.GetClient(e.Context(), id)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Client lookup failed",
			slog.Any("error", err),
			slog.String("client_id", id),
		)
		return nil, nil, e.JSON(http.StatusInternalServerError, errServerError)
	}
	if client == nil {
		return fail("Invalid client")
	}

	if secret == "" && !client.IsPublic() {
		return fail("Client requires a secret")
	}

	if secret != "" && !client.VerifySecret(secret) {
		return fail("Client provided an invalid secret")
	}

	return form, client, nil
}

func (p *Provider) handleAuthorizationCodeGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	code := form.Get(ParamCode)
	redirectURI := form.Get(ParamRedirectURI)
	verifier := form.Get(ParamCodeVerifier)

	if code == "" {
		return e.JSON(http.StatusBadRequest, errMissingCode)
	}
	if verifier == "" {
		return e.JSON(http.StatusBadRequest, errMissingCodeVerifier)
	}

	data, err := p.sessionStore.GetAuthCode(e.Context(), code)
	if err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Failed to retrieve auth code",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusBadRequest, errInvalidAuthCode)
	}

	// Guarantee single use:
	_ = p.sessionStore.DelAuthCode(e.Context(), code)

	if data.ClientID != client.ID() {
		p.logger.DebugContext(
			e.Context(),
			"Client ID mismatch during code exchange",
		)
		return e.JSON(http.StatusBadRequest, errClientMismatch)
	}
	if redirectURI != "" && data.RedirectURI != redirectURI {
		p.logger.DebugContext(
			e.Context(),
			"Redirect URI mismatch during code exchange",
		)
		return e.JSON(http.StatusBadRequest, errRedirectURIMismatch)
	}

	if !pkce.Verify(
		verifier,
		data.CodeChallenge,
		data.CodeChallengeMethod,
	) {
		p.logger.DebugContext(
			e.Context(),
			"PKCE verification failed",
		)
		return e.JSON(http.StatusBadRequest, errPKCEVerificationFailed)
	}

	return p.issue(e, client.ID(), data.UserID, data.Scope, true)
}

func (p *Provider) handleClientCredentialsGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	scope := form.Get(ParamScope)
	if scope != "" && !client.CanUseScope(scope) {
		p.logger.DebugContext(
			e.Context(),
			"Scope not allowed for client credentials",
			slog.String("scope", scope),
		)
		return e.JSON(http.StatusBadRequest, errScopeNotAllowed)
	}

	// Client Credentials flow doesn't have a user context; the subject is the
	// client. Typically, refresh tokens are NOT issued for client credentials.
	return p.issue(e, client.ID(), "", scope, false)
}

func (p *Provider) handleRefreshTokenGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	token := form.Get(ParamRefreshToken)
	if token == "" {
		return e.JSON(http.StatusBadRequest, errMissingRefreshToken)
	}

	data, err := p.sessionStore.GetRefreshToken(e.Context(), token)
	if err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Failed to retrieve refresh token",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusBadRequest, errInvalidRefreshToken)
	}

	if data.ClientID != client.ID() {
		p.logger.DebugContext(
			e.Context(),
			"Client ID mismatch during refresh token exchange",
		)
		return e.JSON(http.StatusBadRequest, errClientMismatch)
	}

	// Revoke the old refresh token to issue a new one.
	_ = p.sessionStore.DelRefreshToken(e.Context(), token)

	return p.issue(e, client.ID(), data.UserID, data.Scope, true)
}

// issue orchestrates the creation of signed Access Tokens (JWT) and
// opaque refresh tokens.
func (p *Provider) issue(
	e *router.Exchange,
	clientID, userID, scope string,
	refresh bool,
) error {
	claims := &auth.Claims{
		Reserved: jwt.Reserved{Sub: userID},
		Scp:      scope,
	}

	if userID == "" {
		claims.Sub = clientID
	} else if u, err := p.userStore.GetUser(e.Context(), userID); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve user for claims",
			slog.Any("error", err),
			slog.String("user_id", userID),
		)
	} else if u != nil {
		claims.Rol = u.Roles()
	} else {
		p.logger.DebugContext(
			e.Context(),
			"Failed to retrieve user for claims",
			slog.String("user_id", userID),
		)
	}

	token, err := p.signer.Sign(claims)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to sign access token",
			slog.Any("error", err),
			slog.String("client_id", clientID),
			slog.String("user_id", userID),
		)
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	res := TokenResponse{
		AccessToken: string(token),
		TokenType:   auth.Scheme,
		ExpiresIn:   int(p.accessTokenLifetime.Seconds()),
		Scope:       scope,
	}

	if refresh {
		token, err := opaque()
		if err != nil {
			p.logger.ErrorContext(
				e.Context(),
				"Failed to generate opaque refresh token",
				slog.Any("error", err),
				slog.String("client_id", clientID),
				slog.String("user_id", userID),
			)
			return e.JSON(http.StatusInternalServerError, errServerError)
		}

		err = p.sessionStore.AddRefreshToken(e.Context(), RefreshToken{
			Token:    token,
			ClientID: clientID,
			UserID:   userID,
			Scope:    scope,
			Lifetime: p.refreshTokenLifetime,
		})
		if err != nil {
			p.logger.ErrorContext(
				e.Context(),
				"Failed to store refresh token",
				slog.Any("error", err),
				slog.String("client_id", clientID),
				slog.String("user_id", userID),
			)
			return e.JSON(http.StatusInternalServerError, errServerError)
		}
		res.RefreshToken = token
	}

	return e.JSON(http.StatusOK, res)
}

// Token creates a cryptographically secure random string intended for use as
// an opaque token.
func opaque() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
