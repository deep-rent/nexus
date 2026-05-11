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
	"net/url"
	"strings"
	"time"
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// Client represents an OAuth 2.0 registered client application.
//
// Implementations are responsible for determining which grant types and scopes
// a specific client is authorized to use, as well as managing redirect URI
// whitelists and secrets.
type Client interface {
	// ID returns the unique identifier for the client.
	ID() string
	// Public indicates if the client is capable of keeping a secret (e.g.,
	// false for SPAs, true for confidential services).
	Public() bool
	// VerifySecret checks if the provided secret matches the client's registered
	// secret.
	VerifySecret(secret string) bool
	// VerifyRedirectURI checks if the specified URI is an allowed redirect
	// destination for the client.
	VerifyRedirectURI(uri string) bool
	// CanUseGrant checks if the client is authorized to use the given grant type.
	CanUseGrant(grant GrantType) bool
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

// Subject represents an authenticated resource owner, typically a user.
//
// Implementations wrap the primary key and permission set. They are managed
// via [SubjectStore].
type Subject interface {
	// ID returns the unique identifier for the subject.
	ID() string
	// Roles returns the list of roles assigned to the subject, used to populate
	// the roles claim in access tokens.
	Roles() []string
}

// SubjectStore provides data access and authentication for resource owners.
//
// It is used by the [Provider] to authenticate subjects during the login flow
// and to resolve identities during authorization and token issuance.
type SubjectStore interface {
	// Authenticate validates subject credentials.
	//
	// If credentials are valid, it must return the subject and nil.
	// If authentication fails (e.g., wrong password), it must return nil and nil.
	// It should return an error only if the underlying storage lookup fails.
	Authenticate(ctx context.Context, username, password string) (Subject, error)
	// GetSubject retrieves a subject by their unique ID.
	//
	// If the user is found, it must return the subject and nil.
	// If the user is not found, it must return nil and nil.
	// It should return an error only if the storage lookup fails.
	GetSubject(ctx context.Context, id string) (Subject, error)
	// GetSubjectBySession retrieves the authenticated subject via their
	// session key.
	//
	// If the session is valid, it must return the subject and nil.
	// If the session is missing, invalid, or expired, it must return nil and nil.
	// It should return an error only if the storage lookup fails.
	GetSubjectBySession(ctx context.Context, key string) (Subject, error)
	// CreateSession stores the session mapping for the authenticated user.
	//
	// It should return an error only if the persistence operation fails.
	CreateSession(ctx context.Context, key, userID string) error
	// DeleteSession removes the session mapping associated with the key.
	//
	// It should return an error only if the removal operation fails.
	DeleteSession(ctx context.Context, key string) error
}

// AuthCode holds the temporary state bound to an authorization code.
//
// These objects should have a short lifespan (usually 1–10 minutes) and
// must be deleted immediately after a single use to prevent replay attacks.
type AuthCode struct {
	// Code is the unique, high-entropy string sent to the client.
	Code string
	// ClientID is the ID of the client that requested the code.
	ClientID string
	// RedirectURI is the URI provided during the initial authorization
	// request. It must be stored to ensure the token exchange request
	// uses the exact same URI.
	RedirectURI string
	// Scope is the list of permissions approved by the resource owner.
	Scope string
	// SubjectID is the unique identifier of the authenticated resource owner.
	SubjectID string
	// CodeChallenge is the challenge string used for PKCE validation.
	CodeChallenge string
	// CodeChallengeMethod is the hashing algorithm used for PKCE validation.
	CodeChallengeMethod string
	// Lifetime defines when this code expires.
	Lifetime time.Duration
}

// RefreshToken holds the state bound to a refresh token.
//
// Refresh tokens allow clients to obtain new access tokens without
// re-authenticating the subject. They generally have a much longer
// lifespan than authorization codes.
type RefreshToken struct {
	// Token is the unique, high-entropy string representing the refresh token.
	Token string
	// ClientID is the identifier of the client authorized to use this token.
	ClientID string
	// SubjectID identifies the subject who authorized the initial request.
	// This remains empty for Client Credentials grants.
	SubjectID string
	// Scope represents the permissions granted for the duration of
	// this session.
	Scope string
	// Lifetime defines the expiration window of this specific token.
	Lifetime time.Duration
}

// SessionStore abstracts the persistence layer for ephemeral authorization
// artifacts.
//
// Implementations must handle the lifecycle of authorization codes and
// refresh tokens. These artifacts usually have a limited TTL.
type SessionStore interface {
	// GetAuthCode retrieves an authorization code by its value.
	//
	// If found, it must return the data and nil.
	// If not found or expired, it must return an empty value and nil.
	// It should return an error only if the storage lookup fails.
	GetAuthCode(ctx context.Context, code string) (AuthCode, error)
	// CreateAuthCode stores a new authorization code.
	//
	// It should return an error only if the persistence operation fails.
	CreateAuthCode(ctx context.Context, data AuthCode) error
	// DeleteAuthCode removes an authorization code. This function is used to
	// ensure single-use of authorization codes, thus preventing replay attacks.
	//
	// It should return an error only if the removal operation fails.
	DeleteAuthCode(ctx context.Context, code string) error
	// GetRefreshToken retrieves a refresh token by its value.
	//
	// If found, it must return the data and nil.
	// If not found or expired, it must return an empty value and nil.
	// It should return an error only if the storage lookup fails.
	GetRefreshToken(ctx context.Context, token string) (RefreshToken, error)
	// CreateRefreshToken stores a new refresh token.
	//
	// It should return an error only if the persistence operation fails.
	CreateRefreshToken(ctx context.Context, data RefreshToken) error
	// DeleteRefreshToken removes a refresh token (e.g., during recovation or
	// rotation).
	//
	// It should return an error only if the removal operation fails.
	DeleteRefreshToken(ctx context.Context, token string) error
}

const (
	ErrorCodeAccessDenied            = "access_denied"
	ErrorCodeInvalidClient           = "invalid_client"
	ErrorCodeInvalidGrant            = "invalid_grant"
	ErrorCodeInvalidRequest          = "invalid_request"
	ErrorCodeInvalidScope            = "invalid_scope"
	ErrorCodeServerError             = "server_error"
	ErrorCodeTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorCodeUnauthorizedClient      = "unauthorized_client"
	ErrorCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrorCodeUnsupportedResponseType = "unsupported_response_type"
)

// Error represents an RFC 6749 compliant error response.
type Error struct {
	// Status is the HTTP status code (e.g., 400, 401) to send when returning
	// this error.
	Status int `json:"-"`
	// Code is the machine-readable error identifier (e.g., "invalid_grant").
	Code string `json:"error"`
	// Description is an optional human-readable explanation providing additional
	// context for developers.
	Description string `json:"error_description,omitempty"`
	// URI is an optional link to a web page providing further information about
	// the error type.
	URI string `json:"error_uri,omitempty"`
}

// Error implements the standard [error] interface. It builds a formatted string
// suitable for logging.
func (e Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Query converts the error into query parameters for use in 302 Redirects.
// This is typically used during the Authorization Code flow when validation
// fails at the authorization endpoint.
func (e Error) Query() url.Values {
	params := url.Values{}
	params.Set("error", e.Code)
	if e.Description != "" {
		params.Set("error_description", e.Description)
	}
	if e.URI != "" {
		params.Set("error_uri", e.URI)
	}
	return params
}

// Proposal represents the raw input of an OAuth 2.0 grant request. It
// encapsulates the verified identity of the requesting client and the
// unvalidated parameters provided in the request body.
type Proposal struct {
	// Client is the authenticated entity making the request (read-only).
	Client   Client
	Sessions SessionStore
	Logger   *slog.Logger
	// data contains the raw form values.
	data url.Values
}

// Get retrieves a grant-specific field from the HTTP request body.
// If no such field exists, an empty string is returned.
func (p *Proposal) Get(key string) string {
	return p.data.Get(key)
}

// Has checks if a grant-specific field is present in the HTTP request body.
func (p *Proposal) Has(key string) bool {
	return p.data.Has(key)
}

// Issuance defines the parameters for issuing tokens after a successful grant
// authorization.
type Issuance struct {
	// Subject identifies subject of the issued tokens. For machine-to-machine
	// requests, this field should be left empty to treat the client itself as
	// the subject.
	Subject string
	// Scope represents the finalized, space-delimited list of permissions
	// granted to the client. This may be a subset of the requested scopes
	// based on server policy or user consent.
	Scope string
	// Refreshable determines if the authorization server should generate
	// a refresh token. While usually determined by the grant type, this allows
	// for granular control based on client policy or requested offline access.
	Refreshable bool
}

// Grant defines the logic for a specific OAuth 2.0 grant type (e.g.,
// Authorization Code, Client Credentials, or Refresh Token).
//
// Implementations are responsible for verifying the grant-specific credentials
// provided in the [Proposal] and determining the identity and permissions
// associated with the resulting tokens.
type Grant interface {
	// Type returns the grant type associated with the implementation.
	Type() GrantType
	// Authorize validates the incoming proposal against the requirements of the
	// specific grant type.
	//
	// If the credentials are valid, it returns a result object containing the
	// subject and scope. If validation fails due to invalid credentials,
	// expired codes, or insufficient permissions, it returns nil and an [Error].
	// Other types of errors will be handled as unexpected failures.
	Authorize(ctx context.Context, pro *Proposal) (*Issuance, error)
}

// TokenResponse outlines the payload returned after a successful token grant.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IntrospectionResponse outlines the RFC 7662 compliant JSON payload.
type IntrospectionResponse struct {
	Active   bool      `json:"active"`
	ClientID string    `json:"client_id,omitempty"`
	Scope    string    `json:"scope,omitempty"`
	Jti      string    `json:"jti,omitempty"`
	Iss      string    `json:"iss,omitempty"`
	Aud      []string  `json:"aud,omitempty"`
	Sub      string    `json:"sub,omitempty"`
	Iat      time.Time `json:"iat,omitzero,format:unix"`
	Exp      time.Time `json:"exp,omitzero,format:unix"`
	Nbf      time.Time `json:"nbf,omitzero,format:unix"`
}

// LoginRequest represents the payload for the resource owner login endpoint.
type LoginRequest struct {
	Username string `json:"username" valid:",required"`
	Password string `json:"password" valid:",required"`
}

// VerifyRedirectURI checks a URI against a list of wildcard patterns.
func VerifyRedirectURI(uri string, whitelist []string) bool {
	for _, pattern := range whitelist {
		if match(uri, pattern) {
			return true
		}
	}
	return false
}

// match checks if a string matches a wildcard pattern.
func match(s, pattern string) bool {
	// If no wildcard, do a direct comparison.
	if !strings.Contains(pattern, "*") {
		return s == pattern
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return true
	}

	// Ensure the string starts with the first part of the pattern.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}

	p := s[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		// If it's the last part, it must be a suffix.
		if i == len(parts)-1 {
			return strings.HasSuffix(p, parts[i])
		}

		// Find the next segment.
		idx := strings.Index(p, parts[i])
		if idx == -1 {
			return false
		}
		p = p[idx+len(parts[i]):]
	}

	return true
}

// opaque generates a high-entropy, base64-encoded string suitable for use as
// a secure token, such as an authorization code, refresh token, or session key.
func opaque() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
