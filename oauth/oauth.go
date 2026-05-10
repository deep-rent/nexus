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
	"strings"
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
//
// Implementations are responsible for determining which grant types and scopes
// a specific client is authorized to use, as well as managing redirect URI
// whitelists and secrets.
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
	// destination. Implementation must perform exact string matching or use a
	// whitelist.
	VerifyRedirectURI(uri string) bool
	// CanUseGrant checks if the client is authorized to use the specified grant
	// type (e.g., "authorization_code", "client_credentials").
	CanUseGrant(grant string) bool
	// CanUseScope checks if the client is allowed to request the specified scope.
	CanUseScope(scope string) bool
}

// ClientStore provides data access for registered OAuth 2.0 clients.
//
// Implementations must bridge the library to the underlying persistence layer.
type ClientStore interface {
	// GetClient retrieves a client by its unique ID.
	//
	// If the client is found, it must return the client and nil.
	// If the client is not found, it must return nil and nil.
	// It should return an error only if the underlying storage lookup fails.
	GetClient(ctx context.Context, id string) (Client, error)
}

// User represents an authenticated resource owner.
//
// Implementations wrap user data such as primary keys and permission sets.
type User interface {
	// ID returns the unique identifier for the user.
	ID() string
	// Roles returns the list of roles assigned to the user, used to populate
	// the "rol" claim in access tokens.
	Roles() []string
}

// UserStore provides data access and authentication for resource owners.
//
// It is used by the Provider to authenticate users during the login flow and
// to resolve user identities during authorization and token issuance.
type UserStore interface {
	// Authenticate validates user credentials.
	//
	// If credentials are valid, it must return the User and nil.
	// If authentication fails (e.g., wrong password), it must return nil and nil.
	// It should return an error only if the underlying storage lookup fails.
	Authenticate(ctx context.Context, username, password string) (User, error)
	// GetUser retrieves a user by their unique ID.
	//
	// If the user is found, it must return the User and nil.
	// If the user is not found, it must return nil and nil.
	// It should return an error only if the storage lookup fails.
	GetUser(ctx context.Context, id string) (User, error)
	// GetUserBySession retrieves the authenticated user via their session key.
	//
	// If the session is valid, it must return the User and nil.
	// If the session is missing, invalid, or expired, it must return nil and nil.
	// It should return an error only if the storage lookup fails.
	GetUserBySession(ctx context.Context, key string) (User, error)
	// CreateSession stores the session mapping for the authenticated user.
	//
	// It should return an error only if the persistence operation fails.
	CreateSession(ctx context.Context, key, userID string) error
	// DeleteSession removes the session mapping associated with the key.
	//
	// It should return an error only if the removal operation fails.
	DeleteSession(ctx context.Context, key string) error
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
//
// Implementations must handle the lifecycle of authorization codes and
// refresh tokens. These artifacts usually have a limited TTL.
type SessionStore interface {
	// GetAuthCode retrieves an authorization code by its value.
	//
	// If found, it must return the data and nil.
	// If not found or expired, it must return an empty AuthCode and nil.
	// It should return an error only if the storage lookup fails.
	GetAuthCode(ctx context.Context, code string) (AuthCode, error)
	// CreateAuthCode stores a new authorization code.
	//
	// It should return an error only if the persistence operation fails.
	CreateAuthCode(ctx context.Context, data AuthCode) error
	// DeleteAuthCode removes an authorization code.
	// It is used to ensure single-use of authorization codes.
	DeleteAuthCode(ctx context.Context, code string) error
	// GetRefreshToken retrieves a refresh token by its value.
	//
	// If found, it must return the data and nil.
	// If not found or expired, it must return an empty RefreshToken and nil.
	// It should return an error only if the storage lookup fails.
	GetRefreshToken(ctx context.Context, token string) (RefreshToken, error)
	// CreateRefreshToken stores a new refresh token.
	//
	// It should return an error only if the persistence operation fails.
	CreateRefreshToken(ctx context.Context, data RefreshToken) error
	// DeleteRefreshToken removes a refresh token.
	//
	// It should return an error only if the removal operation fails.
	DeleteRefreshToken(ctx context.Context, token string) error
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

	// Logger is used for structured logging. Defaults to [slog.Default].
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

// NewProvider creates a new OAuth 2.0 provider with the specified
// configuration.
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
	r.HandleFunc("GET /auth/authorize", p.Authorize)
	r.HandleFunc("POST /auth/authorize", p.Authorize)
	r.HandleFunc("POST /auth/token", p.Token)
	r.HandleFunc("POST /auth/introspect", p.Introspect)
	r.HandleFunc("POST /auth/revoke", p.Revoke)
	r.HandleFunc("POST /auth/login", p.Login)
	r.HandleFunc("POST /auth/logout", p.Logout)
}

// Error returns an OAuth 2.0 compliant error response as JSON.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Error implements the standard error interface.
func (e Error) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

func (e Error) Query() url.Values {
	params := url.Values{}
	params.Set("error", e.Code)
	if e.Description != "" {
		params.Set("error_description", e.Description)
	}
	return params
}

const (
	CodeAccessDenied            = "access_denied"
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeInvalidScope            = "invalid_scope"
	CodeServerError             = "server_error"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeUnsupportedResponseType = "unsupported_response_type"
)

var (
	errAccessDenied                   = Error{Code: CodeAccessDenied, Description: "user authentication required"}
	errClientAuthFailed               = Error{Code: CodeInvalidClient, Description: "client authentication failed"}
	errClientMismatch                 = Error{Code: CodeInvalidGrant, Description: "client mismatch"}
	errClientNotFound                 = Error{Code: CodeInvalidClient, Description: "client not found"}
	errGrantNotAllowed                = Error{Code: CodeUnauthorizedClient, Description: "grant type not allowed for client"}
	errInvalidAuthCode                = Error{Code: CodeInvalidGrant, Description: "invalid or expired authorization code"}
	errInvalidFormBody                = Error{Code: CodeInvalidRequest, Description: "invalid form body"}
	errInvalidRedirectURI             = Error{Code: CodeInvalidRequest, Description: "invalid redirect URI"}
	errInvalidRefreshToken            = Error{Code: CodeInvalidGrant, Description: "invalid or expired refresh token"}
	errMissingClientID                = Error{Code: CodeInvalidRequest, Description: "missing client ID"}
	errMissingCode                    = Error{Code: CodeInvalidRequest, Description: "missing code"}
	errMissingCodeChallenge           = Error{Code: CodeInvalidRequest, Description: "code challenge is required"}
	errMissingCodeVerifier            = Error{Code: CodeInvalidRequest, Description: "missing code verifier"}
	errMissingRedirectURI             = Error{Code: CodeInvalidRequest, Description: "missing redirect URI"}
	errMissingRefreshToken            = Error{Code: CodeInvalidRequest, Description: "missing refresh token"}
	errMissingToken                   = Error{Code: CodeInvalidRequest, Description: "missing token"}
	errPKCEVerificationFailed         = Error{Code: CodeInvalidGrant, Description: "PKCE verification failed"}
	errRedirectURIMismatch            = Error{Code: CodeInvalidGrant, Description: "redirect URI mismatch"}
	errScopeNotAllowed                = Error{Code: CodeInvalidScope, Description: "requested scope is not allowed"}
	errServerError                    = Error{Code: CodeServerError, Description: "unexpected internal error"}
	errUnauthorizedGrantType          = Error{Code: CodeUnauthorizedClient, Description: "client cannot use requested grant type"}
	errUnsupportedCodeChallengeMethod = Error{Code: CodeInvalidRequest, Description: "unsupported code challenge method"}
	errUnsupportedGrantType           = Error{Code: CodeUnsupportedGrantType, Description: "grant type not supported"}
	errUnsupportedResponseType        = Error{Code: CodeUnsupportedResponseType, Description: "only code response type is supported"}
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
	Active   bool   `json:"active"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`

	Jti string    `json:"jti,omitempty"`
	Iss string    `json:"iss,omitempty"`
	Aud []string  `json:"aud,omitempty"`
	Sub string    `json:"sub,omitempty"`
	Iat time.Time `json:"iat,omitzero,format:unix"`
	Exp time.Time `json:"exp,omitzero,format:unix"`
	Nbf time.Time `json:"nbf,omitzero,format:unix"`
}

// Authorize validates the parameters and redirects the user with an auth
// code. It implements RFC 6749 Section 4.1.1.
func (p *Provider) Authorize(e *router.Exchange) error {
	form := e.Query()

	// 1. Extract and validate the client identifier.
	clientID := form.Get(ParamClientID)
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

	// 2. Validate the redirect URI.
	// If the redirect URI is missing or invalid, we MUST NOT redirect the
	// user-agent back to the client. We inform the resource owner directly.
	redirectURI := form.Get(ParamRedirectURI)
	if redirectURI == "" {
		return e.JSON(http.StatusBadRequest, errMissingRedirectURI)
	}
	if !client.VerifyRedirectURI(redirectURI) {
		return e.JSON(http.StatusBadRequest, errInvalidRedirectURI)
	}

	responseType := form.Get(ParamResponseType)
	scope := form.Get(ParamScope)
	state := form.Get(ParamState)
	codeChallenge := form.Get(ParamCodeChallenge)
	codeChallengeMethod := form.Get(ParamCodeChallengeMethod)

	// 3. Define the error redirect helper.
	sendError := func(red Error) error {
		q := red.Query()
		// RFC 6749 Section 4.1.2.1: The state parameter is REQUIRED if it
		// was present in the client authorization request.
		if state != "" {
			q.Set(ParamState, state)
		}
		return e.RedirectTo(redirectURI, q, http.StatusFound)
	}

	// 4. Validate the authorization request parameters.
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

	// 5. Authenticate the resource owner (User).
	// Uses the session cookie established by the /auth/login endpoint.
	cookie, err := e.Cookie(p.sessionCookieName)
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

	// 6. Generate and store the authorization code.
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

	if err := p.sessionStore.CreateAuthCode(
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

	// 7. Redirect the user-agent back to the client.
	params := url.Values{}
	params.Set(ParamCode, code)
	if state != "" {
		params.Set(ParamState, state)
	}

	return e.RedirectTo(redirectURI, params, http.StatusFound)
}

type Credentials struct {
	Username string `json:"username" valid:",required"`
	Password string `json:"password" valid:",required"`
}

// Login authenticates a user and establishes a session cookie.
// It expects a JSON body with "username" and "password" fields.
func (p *Provider) Login(e *router.Exchange) error {
	var c Credentials
	if err := e.BindJSON(&c); err != nil {
		return err
	}

	user, err := p.userStore.Authenticate(
		e.Context(),
		c.Username,
		c.Password,
	)
	if err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"User authentication lookup failed",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusInternalServerError, errServerError)
	}
	if user == nil {
		p.logger.DebugContext(
			e.Context(),
			"User authentication failed: invalid credentials",
		)
		return e.JSON(http.StatusUnauthorized, errAccessDenied)
	}

	key, err := opaque()
	if err != nil {
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	if err := p.userStore.CreateSession(e.Context(), key, user.ID()); err != nil {
		p.logger.ErrorContext(
			e.Context(),
			"Failed to create user session",
			slog.Any("error", err),
		)
		return e.JSON(http.StatusInternalServerError, errServerError)
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

// Logout invalidates the user's session by removing it from the store and
// clearing the session cookie.
func (p *Provider) Logout(e *router.Exchange) error {
	cookie, err := e.Cookie(p.sessionCookieName)
	if err == nil && cookie.Value != "" {
		if err := p.userStore.DeleteSession(e.Context(), cookie.Value); err != nil {
			p.logger.DebugContext(
				e.Context(),
				"Failed to delete user session",
				slog.Any("error", err),
			)
		}
	}

	// Clear the cookie by setting it with a past expiration date and MaxAge -1.
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

// Token processes access token requests and issues credentials.
// It implements RFC 6749 Section 3.2.
func (p *Provider) Token(e *router.Exchange) error {
	// 1. Authenticate the client.
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

	// 2. Dispatch to the appropriate grant handler.
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
	// 1. Authenticate the client making the introspection request.
	form, client, err := p.authenticateClient(e)
	if err != nil {
		return err
	}

	// 2. Extract the token to introspect.
	tok := form.Get(ParamToken)
	if tok == "" {
		return e.JSON(http.StatusBadRequest, errMissingToken)
	}

	// 3. Verify the token signature and temporal claims.
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

	// 4. Return the token metadata if active.
	res := IntrospectionResponse{
		Active:   true,
		ClientID: client.ID(),
		Scope:    claims.Scp.String(),
		Jti:      claims.Jti,
		Iss:      claims.Iss,
		Aud:      claims.Aud,
		Sub:      claims.Sub,
		Iat:      claims.Iat,
		Exp:      claims.Exp,
		Nbf:      claims.Nbf,
	}

	return e.JSON(http.StatusOK, res)
}

// Revoke implements RFC 7009 to allow clients to invalidate their tokens.
func (p *Provider) Revoke(e *router.Exchange) error {
	// 1. Authenticate the client requesting revocation.
	form, _, err := p.authenticateClient(e)
	if err != nil {
		return err
	}

	// 2. Extract the token to revoke.
	tok := form.Get(ParamToken)
	if tok == "" {
		return e.JSON(http.StatusBadRequest, errMissingToken)
	}

	// 3. Delete the token from the session store.
	// Access tokens are stateless JWTs in this implementation, so we primarily
	// care about revoking refresh tokens. RFC 7009 dictates that an invalid
	// or already revoked token should still result in a 200 OK response.
	if err := p.sessionStore.DeleteRefreshToken(e.Context(), tok); err != nil {
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
	// 1. Parse the request body.
	form, err := e.ReadForm()
	if err != nil {
		p.logger.DebugContext(
			e.Context(),
			"Invalid form body",
			slog.Any("error", err),
		)
		return nil, nil, e.JSON(http.StatusBadRequest, errInvalidFormBody)
	}

	// 2. Extract client credentials from headers or form body.
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

	// 3. Retrieve the client from the store.
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

	// 4. Verify the client's credentials.
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
	// 1. Extract the required parameters.
	code := form.Get(ParamCode)
	if code == "" {
		return e.JSON(http.StatusBadRequest, errMissingCode)
	}

	verifier := form.Get(ParamCodeVerifier)
	if verifier == "" {
		return e.JSON(http.StatusBadRequest, errMissingCodeVerifier)
	}

	// 2. Retrieve the authorization code from the session store.
	data, err := p.sessionStore.GetAuthCode(e.Context(), code)
	if err != nil {
		p.logger.ErrorContext(e.Context(), "Failed to retrieve auth code", slog.Any("error", err))
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	// 3. Ensure the code exists.
	if data.Code == "" {
		return e.JSON(http.StatusBadRequest, errInvalidAuthCode)
	}

	// 4. Guarantee single-use by eagerly deleting the code.
	_ = p.sessionStore.DeleteAuthCode(e.Context(), code)

	// 5. Validate the client ID and redirect URI binding.
	if data.ClientID != client.ID() {
		p.logger.DebugContext(
			e.Context(),
			"Client ID mismatch during code exchange",
		)
		return e.JSON(http.StatusBadRequest, errClientMismatch)
	}

	redirectURI := form.Get(ParamRedirectURI)
	if redirectURI != "" && data.RedirectURI != redirectURI {
		p.logger.DebugContext(
			e.Context(),
			"Redirect URI mismatch during code exchange",
		)
		return e.JSON(http.StatusBadRequest, errRedirectURIMismatch)
	}

	// 6. Verify the PKCE code challenge.
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

	// 7. Issue the access and refresh tokens.
	return p.issue(e, client.ID(), data.UserID, data.Scope, true)
}

// handleClientCredentialsGrant issues a token for machine-to-machine
// communication. It implements RFC 6749 Section 4.4.2.
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

// handleRefreshTokenGrant issues a new access token using a refresh token.
// It implements RFC 6749 Section 6.
func (p *Provider) handleRefreshTokenGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	// 1. Extract the required parameters.
	token := form.Get(ParamRefreshToken)
	if token == "" {
		return e.JSON(http.StatusBadRequest, errMissingRefreshToken)
	}

	// 2. Retrieve the refresh token from the session store.
	data, err := p.sessionStore.GetRefreshToken(e.Context(), token)
	if err != nil {
		p.logger.ErrorContext(e.Context(), "Failed to retrieve refresh token", slog.Any("error", err))
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	if data.Token == "" {
		return e.JSON(http.StatusBadRequest, errInvalidRefreshToken)
	}

	if data.ClientID != client.ID() {
		p.logger.DebugContext(
			e.Context(),
			"Client ID mismatch during refresh token exchange",
		)
		return e.JSON(http.StatusBadRequest, errClientMismatch)
	}

	// 3. Revoke the old refresh token to issue a new one (Token Rotation).
	_ = p.sessionStore.DeleteRefreshToken(e.Context(), token)

	// 4. Issue the access and refresh tokens.
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
		Scp:      strings.Fields(scope),
	}

	// Populate claims based on the context of the grant.
	if userID == "" {
		// Client Credentials grant: the subject is the client itself.
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

	// Sign the JWT access token.
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

	// Optionally generate and store an opaque refresh token.
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

		err = p.sessionStore.CreateRefreshToken(e.Context(), RefreshToken{
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
