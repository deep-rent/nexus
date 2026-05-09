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
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

const (
	DefaultAuthCodeTTL     = 5 * time.Minute
	DefaultAccessTokenTTL  = 1 * time.Hour
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
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

// UserStore provides data access and authentication for resource owners.
type UserStore interface {
	// Authenticate validates user credentials and returns the corresponding user ID.
	Authenticate(ctx context.Context, username, password string) (string, error)
	// GetUser retrieves a username by their unique ID.
	GetUser(ctx context.Context, id string) (string, error)
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
	TTL                 time.Duration
}

// RefreshToken holds the state bound to a refresh token.
type RefreshToken struct {
	Token    string
	ClientID string
	UserID   string
	Scope    string
	TTL      time.Duration
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

	ClientStore  ClientStore
	UserStore    UserStore
	SessionStore SessionStore

	// AuthCodeTTL defines how long an authorization code is valid (default: 5 minutes).
	AuthCodeTTL time.Duration
	// AccessTokenTTL defines the lifespan of issued access tokens (default: 1 hour).
	AccessTokenTTL time.Duration
	// RefreshTokenTTL defines the lifespan of refresh tokens (default: 30 days).
	RefreshTokenTTL time.Duration

	// UserExtractor retrieves the authenticated user ID from an incoming router exchange.
	// This is required for the authorization endpoint.
	UserExtractor func(e *router.Exchange) (string, error)

	// Logger is used for structured logging. Defaults to slog.Default().
	Logger *slog.Logger
}

// Provider is the default implementation of the OAuth 2.0 HTTP endpoints.
type Provider struct {
	signer          jwt.Signer
	clientStore     ClientStore
	userStore       UserStore
	sessionStore    SessionStore
	authCodeTTL     time.Duration
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	userExtractor   func(e *router.Exchange) (string, error)
	logger          *slog.Logger
}

// NewProvider creates a new OAuth 2.0 provider with the specified configuration.
func NewProvider(cfg Config) *Provider {
	if cfg.AuthCodeTTL == 0 {
		cfg.AuthCodeTTL = DefaultAuthCodeTTL
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Provider{
		signer:          cfg.Signer,
		clientStore:     cfg.ClientStore,
		userStore:       cfg.UserStore,
		sessionStore:    cfg.SessionStore,
		authCodeTTL:     cfg.AuthCodeTTL,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
		userExtractor:   cfg.UserExtractor,
		logger:          cfg.Logger,
	}
}

// Mount registers the OAuth 2.0 endpoints onto the provided router.
func (p *Provider) Mount(r *router.Router) {
	r.HandleFunc("GET /authorize", p.Authorize)
	r.HandleFunc("POST /authorize", p.Authorize)
	r.HandleFunc("POST /token", p.Token)
}

// IntrospectorConfig contains all necessary dependencies for token introspection.
type IntrospectorConfig struct {
	// Verifier is used to validate access tokens during introspection.
	Verifier    jwt.Verifier[*jwt.DynamicClaims]
	ClientStore ClientStore
	Logger      *slog.Logger
}

// Introspector implements RFC 7662 token introspection.
type Introspector struct {
	verifier    jwt.Verifier[*jwt.DynamicClaims]
	clientStore ClientStore
	logger      *slog.Logger
}

// NewIntrospector creates a new Introspector.
func NewIntrospector(cfg IntrospectorConfig) *Introspector {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Introspector{
		verifier:    cfg.Verifier,
		clientStore: cfg.ClientStore,
		logger:      cfg.Logger,
	}
}

// Mount registers the introspection endpoint onto the provided router.
func (i *Introspector) Mount(r *router.Router) {
	r.HandleFunc("POST /introspect", i.Introspect)
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
	errAccessDenied           = Error{Reason: ReasonAccessDenied, Description: "user authentication required"}
	errClientAuthFailed       = Error{Reason: ReasonInvalidClient, Description: "client authentication failed"}
	errClientMismatch         = Error{Reason: ReasonInvalidGrant, Description: "client mismatch"}
	errClientNotFound         = Error{Reason: ReasonInvalidClient, Description: "client not found"}
	errGrantNotAllowed        = Error{Reason: ReasonUnauthorizedClient, Description: "grant type not allowed for client"}
	errInvalidAuthCode        = Error{Reason: ReasonInvalidGrant, Description: "invalid or expired authorization code"}
	errInvalidFormBody        = Error{Reason: ReasonCodeInvalidRequest, Description: "invalid form body"}
	errInvalidRedirectURI     = Error{Reason: ReasonCodeInvalidRequest, Description: "invalid redirect_uri"}
	errInvalidRefreshToken    = Error{Reason: ReasonInvalidGrant, Description: "invalid or expired refresh token"}
	errMissingClientID        = Error{Reason: ReasonCodeInvalidRequest, Description: "missing client_id"}
	errMissingCodeOrVerifier  = Error{Reason: ReasonCodeInvalidRequest, Description: "missing code or code_verifier"}
	errMissingPKCE            = Error{Reason: ReasonCodeInvalidRequest, Description: "code_challenge is required (PKCE)"}
	errMissingRedirectURI     = Error{Reason: ReasonCodeInvalidRequest, Description: "missing redirect_uri"}
	errMissingRefreshToken    = Error{Reason: ReasonCodeInvalidRequest, Description: "missing refresh_token"}
	errMissingToken           = Error{Reason: ReasonCodeInvalidRequest, Description: "missing token"}
	errPKCEVerificationFailed = Error{Reason: ReasonInvalidGrant, Description: "PKCE verification failed"}
	errRedirectURIMismatch    = Error{Reason: ReasonInvalidGrant, Description: "redirect_uri mismatch"}
	errScopeNotAllowed        = Error{Reason: ReasonInvalidScope, Description: "requested scope is not allowed"}
	errServerError            = Error{Reason: ReasonServerError, Description: "unexpected internal error"}
	errUnauthorizedCodeFlow   = Error{Reason: ReasonUnauthorizedClient, Description: "client cannot use authorization code flow"}
	errUnsupportedGrantType   = Error{Reason: ReasonUnsupportedGrantType, Description: "grant type not supported"}
	errUnsupportedPKCEMethod  = Error{Reason: ReasonCodeInvalidRequest, Description: "unsupported code_challenge_method"}
	errUnsupportedResType     = Error{Reason: ReasonUnsupportedResponseType, Description: "only code response type is supported"}
	errUserExtractorNotConf   = Error{Reason: ReasonServerError, Description: "user extractor not configured"}
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
	Active bool `json:"active"`
}

// AccessTokenClaims extends the standard JWT claims with OAuth 2.0 metadata.
type AccessTokenClaims struct {
	jwt.Reserved
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Username string `json:"username,omitempty"`
}

// Authorize validates the parameters and redirects the user with an auth
// code.
func (p *Provider) Authorize(e *router.Exchange) error {
	q := e.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	resType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")

	if clientID == "" {
		return e.JSON(http.StatusBadRequest, errMissingClientID)
	}

	client, err := p.clientStore.GetClient(e.Context(), clientID)
	if err != nil || client == nil {
		p.logger.Debug("Client not found", slog.String("client_id", clientID))
		return e.JSON(http.StatusUnauthorized, errClientNotFound)
	}

	if redirectURI != "" && !client.VerifyRedirectURI(redirectURI) {
		return e.JSON(http.StatusBadRequest, errInvalidRedirectURI)
	}
	if redirectURI == "" {
		return e.JSON(http.StatusBadRequest, errMissingRedirectURI)
	}

	sendError := func(in Error) error {
		return e.RedirectTo(redirectURI, in.Params(), http.StatusFound)
	}

	if resType != "code" {
		return sendError(errUnsupportedResType)
	}
	if !client.CanUseGrant("authorization_code") {
		return sendError(errUnauthorizedCodeFlow)
	}
	if challenge == "" {
		return sendError(errMissingPKCE)
	}
	if method != "S256" && method != "plain" {
		return sendError(errUnsupportedPKCEMethod)
	}
	if p.userExtractor == nil {
		p.logger.Error("User extractor not configured")
		return sendError(errUserExtractorNotConf)
	}

	userID, err := p.userExtractor(e)
	if err != nil || userID == "" {
		p.logger.Debug("User extraction failed", slog.Any("error", err))
		return sendError(errAccessDenied)
	}

	code, err := opaque()
	if err != nil {
		p.logger.Error("Failed to generate opaque token", slog.Any("error", err))
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	data := AuthCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		UserID:              userID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		TTL:                 p.authCodeTTL,
	}

	if err := p.sessionStore.AddAuthCode(
		e.Context(),
		data,
	); err != nil {
		p.logger.Error("Failed to store authorization code", slog.Any("error", err))
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}

	return e.RedirectTo(redirectURI, params, http.StatusFound)
}

// Token processes access token requests.
func (p *Provider) Token(e *router.Exchange) error {
	form, rErr := e.ReadForm()
	if rErr != nil {
		p.logger.Debug("Invalid form body", slog.Any("error", rErr))
		return e.JSON(http.StatusBadRequest, errInvalidFormBody)
	}

	client, err := authenticateClient(e, p.clientStore, form)
	if err != nil {
		p.logger.Debug("Client authentication failed", slog.Any("error", err))
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return e.JSON(http.StatusUnauthorized, errClientAuthFailed)
	}

	grantType := form.Get("grant_type")
	if !client.CanUseGrant(grantType) {
		p.logger.Debug("Grant type not allowed for client", slog.String("grant_type", grantType))
		return e.JSON(http.StatusBadRequest, errGrantNotAllowed)
	}

	switch grantType {
	case "authorization_code":
		return p.handleAuthorizationCodeGrant(e, form, client)
	case "client_credentials":
		return p.handleClientCredentialsGrant(e, form, client)
	case "refresh_token":
		return p.handleRefreshTokenGrant(e, form, client)
	default:
		return e.JSON(http.StatusBadRequest, errUnsupportedGrantType)
	}
}

// Introspect implements RFC 7662 to determine the active state of an
// OAuth 2.0 token.
func (i *Introspector) Introspect(e *router.Exchange) error {
	form, err := e.ReadForm()
	if err != nil {
		i.logger.Debug("Invalid form body in introspection", slog.Any("error", err))
		return e.JSON(http.StatusBadRequest, errInvalidFormBody)
	}

	if _, err := authenticateClient(e, i.clientStore, form); err != nil {
		i.logger.Debug("Client authentication failed", slog.Any("error", err))
		e.SetHeader("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		return e.JSON(http.StatusUnauthorized, errClientAuthFailed)
	}

	tok := form.Get("token")
	if tok == "" {
		return e.JSON(http.StatusBadRequest, errMissingToken)
	}

	active := true
	if _, err := i.verifier.Verify([]byte(tok)); err != nil {
		// RFC 7662: If the token is invalid, expired, or revoked, the authorization
		// server MUST return an active boolean set to false.
		i.logger.Debug("Token introspection verification failed", slog.Any("error", err))
		active = false
	}
	return e.JSON(http.StatusOK, IntrospectionResponse{Active: active})
}

// authenticateClient resolves and authenticates the client via HTTP Basic Auth or POST form.
func authenticateClient(e *router.Exchange, store ClientStore, form url.Values) (Client, error) {
	clientID, clientSecret, ok := e.R.BasicAuth()
	if !ok {
		clientID = form.Get("client_id")
		clientSecret = form.Get("client_secret")
	}

	if clientID == "" {
		return nil, errors.New("missing client_id")
	}

	client, err := store.GetClient(e.Context(), clientID)
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

func (p *Provider) handleAuthorizationCodeGrant(e *router.Exchange, form url.Values, client Client) error {
	code := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	verifier := form.Get("code_verifier")

	if code == "" || verifier == "" {
		return e.JSON(http.StatusBadRequest, errMissingCodeOrVerifier)
	}

	data, err := p.sessionStore.GetAuthCode(e.Context(), code)
	if err != nil {
		p.logger.Debug("Failed to retrieve auth code", slog.Any("error", err))
		return e.JSON(http.StatusBadRequest, errInvalidAuthCode)
	}

	// Single-use guarantee
	_ = p.sessionStore.DelAuthCode(e.Context(), code)

	if data.ClientID != client.ID() {
		p.logger.Debug("Client ID mismatch during code exchange")
		return e.JSON(http.StatusBadRequest, errClientMismatch)
	}
	if redirectURI != "" && data.RedirectURI != redirectURI {
		p.logger.Debug("Redirect URI mismatch during code exchange")
		return e.JSON(http.StatusBadRequest, errRedirectURIMismatch)
	}

	if !verifyPKCE(verifier, data.CodeChallenge, data.CodeChallengeMethod) {
		p.logger.Debug("PKCE verification failed")
		return e.JSON(http.StatusBadRequest, errPKCEVerificationFailed)
	}

	return p.issueTokens(e, client.ID(), data.UserID, data.Scope, true)
}

func (p *Provider) handleClientCredentialsGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	scope := form.Get("scope")
	if scope != "" && !client.CanUseScope(scope) {
		p.logger.Debug("Scope not allowed for client credentials", slog.String("scope", scope))
		return e.JSON(http.StatusBadRequest, errScopeNotAllowed)
	}

	// Client Credentials flow doesn't have a user context; the subject is the
	// client. Typically, refresh tokens are NOT issued for client credentials.
	return p.issueTokens(e, client.ID(), "", scope, false)
}

func (p *Provider) handleRefreshTokenGrant(
	e *router.Exchange,
	form url.Values,
	client Client,
) error {
	token := form.Get("refresh_token")
	if token == "" {
		return e.JSON(http.StatusBadRequest, errMissingRefreshToken)
	}

	data, err := p.sessionStore.GetRefreshToken(e.Context(), token)
	if err != nil {
		p.logger.Debug("Failed to retrieve refresh token", slog.Any("error", err))
		return e.JSON(http.StatusBadRequest, errInvalidRefreshToken)
	}

	if data.ClientID != client.ID() {
		p.logger.Debug("Client ID mismatch during refresh token exchange")
		return e.JSON(http.StatusBadRequest, errClientMismatch)
	}

	// Revoke the old refresh token to issue a new one.
	_ = p.sessionStore.DelRefreshToken(e.Context(), token)

	return p.issueTokens(e, client.ID(), data.UserID, data.Scope, true)
}

// issueTokens orchestrates the creation of signed Access Tokens (JWT) and
// opaque refresh tokens.
func (p *Provider) issueTokens(
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
	} else if p.userStore != nil {
		// Optionally enhance the claims with a username if available.
		if u, err := p.userStore.GetUser(e.Context(), userID); err == nil && u != "" {
			claims.Username = u
		} else if err != nil {
			p.logger.Debug("Failed to retrieve user for claims", slog.Any("error", err))
		}
	}

	tokenBytes, err := p.signer.Sign(claims)
	if err != nil {
		p.logger.Error("Failed to sign access token", slog.Any("error", err))
		return e.JSON(http.StatusInternalServerError, errServerError)
	}

	res := TokenResponse{
		AccessToken: string(tokenBytes),
		TokenType:   "Bearer",
		ExpiresIn:   int(p.accessTokenTTL.Seconds()),
		Scope:       scope,
	}

	if refresh {
		rt, err := opaque()
		if err != nil {
			p.logger.Error("Failed to generate opaque refresh token", slog.Any("error", err))
			return e.JSON(http.StatusInternalServerError, errServerError)
		}

		err = p.sessionStore.AddRefreshToken(e.Context(), RefreshToken{
			Token:    rt,
			ClientID: clientID,
			UserID:   userID,
			Scope:    scope,
			TTL:      p.refreshTokenTTL,
		})
		if err != nil {
			p.logger.Error("Failed to store refresh token", slog.Any("error", err))
			return e.JSON(http.StatusInternalServerError, errServerError)
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
