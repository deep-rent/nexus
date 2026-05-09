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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
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
	// IsValidRedirectURI checks if the given URI is an allowed redirect
	// destination.
	IsValidRedirectURI(uri string) bool
	// CanUseGrant checks if the client is authorized to use the specified
	// grant type.
	CanUseGrant(grant string) bool
	// CanUseScope checks if the client is allowed to request the specified scope.
	CanUseScope(scope string) bool
}

// User represents an authenticated resource owner.
type User interface {
	// ID returns the unique identifier for the user.
	ID() string
}

// ClientStore provides data access for registered OAuth 2.0 clients.
type ClientStore interface {
	// GetClient retrieves a client by its unique ID.
	GetClient(ctx context.Context, id string) (Client, error)
}

// UserStore provides data access and authentication for resource owners.
type UserStore interface {
	// Authenticate validates user credentials and returns the corresponding User.
	Authenticate(ctx context.Context, username, password string) (User, error)
	// GetUser retrieves a user by their unique ID.
	GetUser(ctx context.Context, id string) (User, error)
}

// AuthCodeData holds the state bound to an authorization code.
type AuthCodeData struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
}

// RefreshTokenData holds the state bound to a refresh token.
type RefreshTokenData struct {
	ClientID string
	UserID   string
	Scope    string
}

// SessionStore abstracts the persistence layer for ephemeral OAuth 2.0
// artifacts.
type SessionStore interface {
	AddAuthCode(ctx context.Context, code string, data AuthCodeData, ttl time.Duration) error
	GetAuthCode(ctx context.Context, code string) (AuthCodeData, error)
	DelAuthCode(ctx context.Context, code string) error
	AddRefreshToken(ctx context.Context, token string, data RefreshTokenData, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, token string) (RefreshTokenData, error)
	DelRefreshToken(ctx context.Context, token string) error
}

// Provider defines the handlers for the core OAuth 2.0 HTTP endpoints.
type Provider interface {
	// HandleAuthorize processes authorization requests (e.g., Authorization Code Flow).
	HandleAuthorize(e *router.Exchange) error
	// HandleToken processes token requests (e.g., Code exchange, Refresh, Client Credentials).
	HandleToken(e *router.Exchange) error
	// HandleIntrospect implements RFC 7662 token introspection.
	HandleIntrospect(e *router.Exchange) error
}

// Config contains all necessary dependencies and settings for the OAuth 2.0 Provider.
type Config struct {
	// Signer is used to mint new access tokens (JWTs).
	Signer jwt.Signer
	// Verifier is used to validate access tokens during introspection.
	Verifier jwt.Verifier[*jwt.DynamicClaims]

	ClientStore  ClientStore
	UserStore    UserStore
	SessionStore SessionStore

	// AuthCodeTTL defines how long an authorization code is valid (default: 5 minutes).
	AuthCodeTTL time.Duration
	// AccessTokenTTL defines the lifespan of issued access tokens (default: 1 hour).
	AccessTokenTTL time.Duration
	// RefreshTokenTTL defines the lifespan of refresh tokens (default: 30 days).
	RefreshTokenTTL time.Duration

	// UserExtractor retrieves the authenticated user from an incoming router exchange.
	// This is required for the authorization endpoint.
	UserExtractor func(e *router.Exchange) (User, error)
}

// provider is the default implementation of the Provider interface.
type provider struct {
	cfg Config
}

// NewProvider creates a new OAuth 2.0 provider with the specified configuration.
func NewProvider(cfg Config) Provider {
	if cfg.AuthCodeTTL == 0 {
		cfg.AuthCodeTTL = 5 * time.Minute
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 1 * time.Hour
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	return &provider{cfg: cfg}
}

// Mount registers the default OAuth 2.0 endpoints onto the provided router.
func Mount(r *router.Router, p Provider) {
	r.HandleFunc("GET /authorize", p.HandleAuthorize)
	r.HandleFunc("POST /authorize", p.HandleAuthorize)
	r.HandleFunc("POST /token", p.HandleToken)
	r.HandleFunc("POST /introspect", p.HandleIntrospect)
}

// Error returns an OAuth 2.0 compliant error response as JSON.
type Error struct {
	Err         string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Error implements the standard error interface.
func (e Error) Error() string {
	if e.Description != "" {
		return e.Err + ": " + e.Description
	}
	return e.Err
}

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
	Active bool `json:"active"`
}

// AccessTokenClaims extends the standard JWT claims with OAuth 2.0 metadata.
type AccessTokenClaims struct {
	jwt.Reserved
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Username string `json:"username,omitempty"`
}

// HandleAuthorize validates the parameters and redirects the user with an auth
// code.
func (p *provider) HandleAuthorize(e *router.Exchange) error {
	q := e.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	resType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")

	if clientID == "" {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "missing client_id"},
		)
	}

	client, err := p.cfg.ClientStore.GetClient(e.Context(), clientID)
	if err != nil || client == nil {
		return e.JSON(
			http.StatusUnauthorized,
			Error{Err: "invalid_client", Description: "client not found"},
		)
	}

	if redirectURI != "" && !client.IsValidRedirectURI(redirectURI) {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "invalid redirect_uri"},
		)
	}
	if redirectURI == "" {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "missing redirect_uri"},
		)
	}

	sendError := func(errCode, desc string) error {
		params := url.Values{}
		params.Set("error", errCode)
		params.Set("error_description", desc)
		if state != "" {
			params.Set("state", state)
		}
		return e.RedirectTo(redirectURI, params, http.StatusFound)
	}

	if resType != "code" {
		return sendError(
			"unsupported_response_type",
			"only code response type is supported",
		)
	}
	if !client.CanUseGrant("authorization_code") {
		return sendError(
			"unauthorized_client",
			"client cannot use authorization code flow",
		)
	}
	if challenge == "" {
		return sendError(
			"invalid_request",
			"code_challenge is required (PKCE)",
		)
	}
	if method != "S256" && method != "plain" {
		return sendError(
			"invalid_request",
			"unsupported code_challenge_method",
		)
	}

	if p.cfg.UserExtractor == nil {
		return sendError(
			"server_error",
			"user extractor not configured",
		)
	}

	user, err := p.cfg.UserExtractor(e)
	if err != nil || user == nil {
		return sendError(
			"access_denied",
			"user authentication required",
		)
	}

	code, err := opaque()
	if err != nil {
		return e.JSON(http.StatusInternalServerError, Error{Err: "server_error"})
	}

	data := AuthCodeData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		UserID:              user.ID(),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
	}

	if err := p.cfg.SessionStore.AddAuthCode(
		e.Context(),
		code,
		data,
		p.cfg.AuthCodeTTL,
	); err != nil {
		return e.JSON(http.StatusInternalServerError, Error{Err: "server_error"})
	}

	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}

	return e.RedirectTo(redirectURI, params, http.StatusFound)
}

// HandleToken processes access token requests.
func (p *provider) HandleToken(e *router.Exchange) error {
	form, rErr := e.ReadForm()
	if rErr != nil {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "invalid form body"},
		)
	}

	client, err := p.authenticateClient(e, form)
	if err != nil {
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return e.JSON(
			http.StatusUnauthorized,
			Error{Err: "invalid_client", Description: "client authentication failed"},
		)
	}

	grantType := form.Get("grant_type")
	if !client.CanUseGrant(grantType) {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "unauthorized_client", Description: "grant type not allowed for client"},
		)
	}

	switch grantType {
	case "authorization_code":
		return p.handleAuthorizationCodeGrant(e, form, client)
	case "client_credentials":
		return p.handleClientCredentialsGrant(e, form, client)
	case "refresh_token":
		return p.handleRefreshTokenGrant(e, form, client)
	default:
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "unsupported_grant_type", Description: "grant type not supported"},
		)
	}
}

// HandleIntrospect implements RFC 7662 to determine the active state of an
// OAuth 2.0 token.
func (p *provider) HandleIntrospect(e *router.Exchange) error {
	form, err := e.ReadForm()
	if err != nil {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "invalid form body"},
		)
	}

	if _, err := p.authenticateClient(e, form); err != nil {
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return e.JSON(
			http.StatusUnauthorized,
			Error{Err: "invalid_client", Description: "client authentication failed"},
		)
	}

	tok := form.Get("token")
	if tok == "" {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "missing token"},
		)
	}

	active := true
	if _, err := p.cfg.Verifier.Verify([]byte(tok)); err != nil {
		// RFC 7662: If the token is invalid, expired, or revoked, the authorization
		// server MUST return an active boolean set to false.
		active = false
	}
	return e.JSON(http.StatusOK, IntrospectionResponse{Active: active})
}

// authenticateClient resolves and authenticates the client via HTTP Basic Auth or POST form.
func (p *provider) authenticateClient(e *router.Exchange, form url.Values) (Client, error) {
	clientID, clientSecret, ok := e.R.BasicAuth()
	if !ok {
		clientID = form.Get("client_id")
		clientSecret = form.Get("client_secret")
	}

	if clientID == "" {
		return nil, errors.New("missing client_id")
	}

	client, err := p.cfg.ClientStore.GetClient(e.Context(), clientID)
	if err != nil || client == nil {
		return nil, errors.New("invalid client")
	}

	if clientSecret == "" && !client.IsPublic() {
		return nil, errors.New("client requires a secret")
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

func (p *provider) handleAuthorizationCodeGrant(e *router.Exchange, form url.Values, client Client) error {
	code := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	verifier := form.Get("code_verifier")

	if code == "" || verifier == "" {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "missing code or code_verifier"},
		)
	}

	data, err := p.cfg.SessionStore.GetAuthCode(e.Context(), code)
	if err != nil {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_grant", Description: "invalid or expired authorization code"},
		)
	}

	// Single-use guarantee
	_ = p.cfg.SessionStore.DelAuthCode(e.Context(), code)

	if data.ClientID != client.ID() {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_grant", Description: "client mismatch"},
		)
	}
	if redirectURI != "" && data.RedirectURI != redirectURI {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_grant", Description: "redirect_uri mismatch"},
		)
	}

	if !verifyPKCE(verifier, data.CodeChallenge, data.CodeChallengeMethod) {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_grant", Description: "PKCE verification failed"},
		)
	}

	return p.issueTokens(e, client.ID(), data.UserID, data.Scope, true)
}

func (p *provider) handleClientCredentialsGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	scope := form.Get("scope")
	if scope != "" && !client.CanUseScope(scope) {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_scope", Description: "requested scope is not allowed"},
		)
	}

	// Client Credentials flow doesn't have a user context; the subject is the
	// client. Typically, refresh tokens are NOT issued for client credentials.
	return p.issueTokens(e, client.ID(), "", scope, false)
}

func (p *provider) handleRefreshTokenGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	token := form.Get("refresh_token")
	if token == "" {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_request", Description: "missing refresh_token"},
		)
	}

	data, err := p.cfg.SessionStore.GetRefreshToken(e.Context(), token)
	if err != nil {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_grant", Description: "invalid or expired refresh token"},
		)
	}

	if data.ClientID != client.ID() {
		return e.JSON(
			http.StatusBadRequest,
			Error{Err: "invalid_grant", Description: "client mismatch"},
		)
	}

	// Revoke the old refresh token to issue a new one.
	_ = p.cfg.SessionStore.DelRefreshToken(e.Context(), token)

	return p.issueTokens(e, client.ID(), data.UserID, data.Scope, true)
}

// issueTokens orchestrates the creation of signed Access Tokens (JWT) and
// opaque refresh tokens.
func (p *provider) issueTokens(
	e *router.Exchange,
	clientID, userID, scope string,
	refresh bool,
) error {
	claims := &AccessTokenClaims{
		Reserved: jwt.Reserved{
			Sub: userID,
		},
		Scope:    scope,
		ClientID: clientID,
	}

	if userID == "" {
		claims.Sub = clientID
	} else if p.cfg.UserStore != nil {
		// Optionally enhance the claims with a username if available
		if u, err := p.cfg.UserStore.GetUser(e.Context(), userID); err == nil && u != nil {
			// Abstract implementation logic would handle custom claims injection
			_ = u // Not strictly required for the foundational flow, but ready.
		}
	}

	tokenBytes, err := p.cfg.Signer.Sign(claims)
	if err != nil {
		return e.JSON(http.StatusInternalServerError, Error{Err: "server_error"})
	}

	res := TokenResponse{
		AccessToken: string(tokenBytes),
		TokenType:   "Bearer",
		ExpiresIn:   int(p.cfg.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}

	if refresh {
		rt, err := opaque()
		if err != nil {
			return e.JSON(http.StatusInternalServerError, Error{Err: "server_error"})
		}

		err = p.cfg.SessionStore.AddRefreshToken(e.Context(), rt, RefreshTokenData{
			ClientID: clientID,
			UserID:   userID,
			Scope:    scope,
		}, p.cfg.RefreshTokenTTL)
		if err != nil {
			return e.JSON(http.StatusInternalServerError, Error{Err: "server_error"})
		}
		res.RefreshToken = rt
	}

	return e.JSON(http.StatusOK, res)
}

// opaque creates a cryptographically secure random string.
func opaque() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// verifyPKCE validates an incoming code verifier against the originally stored
// challenge.
func verifyPKCE(verifier, challenge, method string) bool {
	if len(challenge) == 0 {
		return false
	}

	var expected []byte
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(h[:])
		expected = []byte(encoded)
	case "plain":
		expected = []byte(verifier)
	default:
		return false
	}

	// Ensure constant-time comparison doesn't panic due to unequal lengths.
	if len(expected) != len(challenge) {
		return false
	}

	return subtle.ConstantTimeCompare(expected, []byte(challenge)) == 1
}
