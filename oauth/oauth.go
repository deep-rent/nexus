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

// Package oauth implements the core protocols for an OAuth 2.0 authorization
// server.
//
// The package provides a flexible and extensible framework for issuing access
// tokens to clients. It abstracts the complexity of the OAuth 2.0 flows,
// including Authorization Code, Client Credentials, and Refresh Token grants,
// while allowing developers to provide custom implementations for client and
// session management.
//
// # Architecture
//
// The core of the package is the [Server], which manages the lifecycle of
// authorization requests and token issuance. It relies on a set of interfaces
// ([ClientStore], [SubjectStore], [SessionStore]) that must be implemented to
// bridge the library with the underlying database or persistence layer.
//
// # Usage
//
// To use this package, define a [Config] with your store implementations
// and initialize a [Server] using the desired [Grant] types as options.
//
// Example:
//
//	// 1. Define the configuration with mandatory stores and key vault.
//	cfg := oauth.Config{
//	  Vault:            myVault,
//	  Clients:          myClientStore,
//	  Sessions:         mySessionStore,
//	  Subjects:         mySubjectStore,
//	  Issuer:           "https://id.example.com",
//	  LoginTerminalURI: "https://app.example.com/login",
//	  LoginRedirectURI: "https://app.example.com/dashboard",
//	}
//
//	// 2. Initialize the server and register grants or identity providers.
//	// New panics on invalid configuration.
//	s := oauth.New(cfg,
//	  oauth.WithGrant(oauth.AuthCodeGrant()),
//	  oauth.WithGrant(oauth.ClientCredentialsGrant()),
//	  oauth.WithGrant(oauth.RefreshTokenGrant()),
//	  oauth.WithIdentityProvider("google", myGoogleProvider),
//	)
//
//	// 3. Mount the endpoints onto a router.
//	r := router.New()
//	s.Mount(r, "/oauth")
//
//	// 4. Start serving.
//	http.ListenAndServe(":8080", r)
//
// # Operational notes
//
// The server issues stateless JWT access tokens; only refresh tokens can be
// revoked. The authorization endpoint grants implicit consent: any resource
// owner with an active session is treated as having approved the requested
// scopes, which is appropriate for first-party clients only.
//
// Set [Config.Throttle] to rate limit the credential-verifying endpoints
// and slow down brute-force attempts; see [Throttle] for the trade-offs.
// Because its buckets live in memory, it complements rather than replaces
// volumetric rate limiting at the load balancer or reverse proxy.
//
// Deployments must provide the remaining protections that fall outside this
// package: serve all endpoints over TLS (cookies are marked Secure), and
// back the store interfaces with implementations that honor the atomicity
// and TTL contracts documented on [SessionStore].
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"uuid"

	"github.com/deep-rent/nexus/valid"
)

// GrantType defines the various flows for obtaining an access token.
type GrantType string

const (
	// GrantTypeAuthorizationCode refers to the Authorization Code grant.
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeClientCredentials refers to the Client Credentials grant.
	GrantTypeClientCredentials GrantType = "client_credentials"
	// GrantTypeRefreshToken refers to the Refresh Token grant.
	GrantTypeRefreshToken GrantType = "refresh_token"
	// GrantTypeDeviceCode refers to the Device Code grant.
	GrantTypeDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// Client represents an OAuth 2.0 registered client application.
//
// Implementations are responsible for determining which grant types and scopes
// a specific client is authorized to use, as well as managing redirect URI
// whitelists and secrets.
type Client interface {
	// ID returns the unique identifier for the client.
	ID() uuid.UUID
	// Public indicates if the client is capable of keeping a secret (e.g.,
	// false for SPAs, true for confidential services).
	Public() bool
	// Audience returns the audience for the client. This value will be included
	// in the "aud" claim of access tokens issued to this client. If an empty
	// slice or nil is returned, the claim will be omitted during issuance.
	Audience() []string
	// VerifySecret checks if the provided secret matches the client's
	// registered secret.
	//
	// Implementations must compare in constant time and should persist only
	// a cryptographic hash of the secret — e.g., compare digests with
	// [crypto/subtle.ConstantTimeCompare] — so that neither timing nor a
	// leaked client registry reveals usable credentials.
	VerifySecret(secret string) bool
	// VerifyRedirectURI checks if the specified URI is an allowed redirect
	// destination for the client.
	VerifyRedirectURI(uri string) bool
	// CanUseGrant checks if the client is authorized to use the given grant
	// type.
	CanUseGrant(grant GrantType) bool
	// CanUseScope checks if the client is allowed to request the specified
	// scope. It receives a single scope token (never a space-delimited list);
	// the server splits requested scopes and consults this method per token.
	CanUseScope(scope string) bool
}

// canUseScope reports whether the client may use every scope token in the
// space-delimited scope string.
func canUseScope(c Client, scope string) bool {
	for s := range strings.FieldsSeq(scope) {
		if !c.CanUseScope(s) {
			return false
		}
	}
	return true
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
	GetClient(ctx context.Context, id uuid.UUID) (Client, error)
}

// Subject represents an authenticated resource owner, typically a user.
//
// Implementations wrap the primary key and permission set. They are managed
// via [SubjectStore].
type Subject interface {
	// ID returns the unique identifier for the subject.
	ID() uuid.UUID
	// Roles returns the list of roles assigned to the subject, used to populate
	// the roles claim in access tokens.
	Roles() []string
}

// SubjectStore provides data access and authentication for resource owners.
//
// It is used by the [Server] to authenticate subjects during the login flow
// and to resolve identities during authorization and token issuance.
type SubjectStore interface {
	// Authenticate validates subject credentials.
	//
	// If credentials are valid, it must return the subject and nil.
	// If authentication fails (e.g., wrong password), it must return nil and
	// nil. It should return an error only if the underlying storage lookup
	// fails.
	Authenticate(
		ctx context.Context,
		username, password string,
	) (Subject, error)
	// GetSubject retrieves a subject by their unique ID.
	//
	// If the user is found, it must return the subject and nil.
	// If the user is not found, it must return nil and nil.
	// It should return an error only if the storage lookup fails.
	GetSubject(ctx context.Context, id uuid.UUID) (Subject, error)
	// GetSubjectByExternalID retrieves a subject linked to an external
	// identity provider.
	//
	// This is used for social login flows. If no local subject is linked to
	// the external ID, it returns nil, nil (allowing for Just-In-Time
	// provisioning if the implementation chooses to do so).
	GetSubjectByExternalID(
		ctx context.Context,
		provider string, identity Claimant,
	) (Subject, error)
	// GetSubjectBySession retrieves the authenticated subject via their
	// session key.
	//
	// If the session is valid, it must return the subject and nil.
	// If the session is missing, invalid, or expired, it must return nil and
	// nil. It should return an error only if the storage lookup fails.
	GetSubjectBySession(ctx context.Context, key string) (Subject, error)
	// CreateSession stores the session mapping for the authenticated user.
	//
	// It should return an error only if the persistence operation fails.
	CreateSession(ctx context.Context, key string, subjectID uuid.UUID) error
	// DeleteSession removes the session mapping associated with the key.
	//
	// It should return an error only if the removal operation fails.
	DeleteSession(ctx context.Context, key string) error
}

// Digest is the SHA-256 fingerprint of a bearer artifact (authorization
// code, refresh token, device code, or user code), encoded as an unpadded
// base64url string.
//
// The [Server] hashes every artifact before it crosses the [SessionStore]
// boundary, so implementations never see plaintext bearer secrets: a leaked
// datastore cannot be replayed against the server. Implementations should
// treat digests as opaque keys and persist them as-is.
type Digest string

// NewDigest computes the [Digest] of the given artifact value.
func NewDigest(value string) Digest {
	sum := sha256.Sum256([]byte(value))
	return Digest(base64.RawURLEncoding.EncodeToString(sum[:]))
}

// AuthCode holds the temporary state bound to an authorization code.
//
// These objects should have a short lifespan (usually 1–10 minutes) and
// must be deleted immediately after a single use to prevent replay attacks.
type AuthCode struct {
	// Code is the digest of the high-entropy code sent to the client. The
	// plaintext value never reaches the store.
	Code Digest `json:"code"`
	// ClientID is the ID of the client that requested the code.
	ClientID uuid.UUID `json:"client_id"`
	// RedirectURI is the URI provided during the initial authorization
	// request. It must be stored to ensure the token exchange request
	// uses the exact same URI.
	RedirectURI string `json:"redirect_uri"`
	// Scope is the list of permissions approved by the resource owner.
	Scope string `json:"scope"`
	// SubjectID is the unique identifier of the authenticated resource owner.
	SubjectID uuid.UUID `json:"subject_id"`
	// CodeChallenge is the challenge string used for PKCE validation.
	CodeChallenge string `json:"code_challenge"`
	// CodeChallengeMethod is the hashing algorithm used for PKCE validation.
	CodeChallengeMethod string `json:"code_challenge_method"`
	// ExpiresAt defines when this code expires, as a UNIX timestamp in
	// seconds.
	ExpiresAt int64 `json:"expires_at"`
}

// RefreshToken holds the state bound to a refresh token.
//
// Refresh tokens allow clients to obtain new access tokens without
// re-authenticating the subject. They generally have a much longer
// lifespan than authorization codes.
type RefreshToken struct {
	// Token is the digest of the high-entropy refresh token issued to the
	// client. The plaintext value never reaches the store.
	Token Digest `json:"token"`
	// ClientID is the identifier of the client authorized to use this token.
	ClientID uuid.UUID `json:"client_id"`
	// SubjectID identifies the subject who authorized the initial request.
	// This remains the zero UUID for Client Credentials grants.
	SubjectID uuid.UUID `json:"subject_id,omitzero"`
	// Scope represents the permissions granted for the duration of
	// this session.
	Scope string `json:"scope"`
	// ExpiresAt defines when this specific token expires, as a UNIX timestamp
	// in seconds.
	ExpiresAt int64 `json:"expires_at"`
}

// DeviceCodeStatus represents the state of a device authorization request
// during the polling process of a Device Authorization Grant.
type DeviceCodeStatus string

const (
	// DeviceCodeStatusPending indicates the authorization request is still
	// active and the user has not yet completed the verification steps.
	// The client should continue to poll the token endpoint.
	DeviceCodeStatusPending DeviceCodeStatus = "pending"

	// DeviceCodeStatusDenied indicates the authorization request was rejected
	// by the user or the authorization server. The client must stop polling.
	DeviceCodeStatusDenied DeviceCodeStatus = "denied"

	// DeviceCodeStatusAuthorized indicates the user has successfully approved
	// the request. The client can now proceed to use the device code to
	// obtain tokens.
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
)

// DeviceCode holds the state bound to a device authorization request.
//
// Unlike authorization codes, device codes are polled by the client over a
// longer period until the resource owner completes the authorization on a
// separate device.
type DeviceCode struct {
	// DeviceCode is the digest of the high-entropy code polled by the client.
	// The plaintext value never reaches the store.
	DeviceCode Digest `json:"device_code"`
	// UserCode is the digest of the short, user-friendly code entered by the
	// resource owner. The plaintext value never reaches the store.
	UserCode Digest `json:"user_code"`
	// ClientID is the ID of the client that requested the code.
	ClientID uuid.UUID `json:"client_id"`
	// SubjectID is the unique identifier of the authenticated resource owner.
	// It remains the zero UUID until the user authorizes the request.
	SubjectID uuid.UUID `json:"subject_id,omitzero"`
	// Scope is the list of permissions approved by the resource owner.
	Scope string `json:"scope"`
	// Status indicates the current state: "pending", "authorized", or "denied".
	Status DeviceCodeStatus `json:"status"`
	// ExpiresAt defines when this code is no longer valid, as a UNIX timestamp
	// in seconds.
	ExpiresAt int64 `json:"expires_at"`
	// Interval is the minimum number of seconds the client must wait between
	// polling attempts (RFC 8628 Section 3.5). Zero disables rate limiting.
	Interval int64 `json:"interval,omitzero"`
	// LastPolledAt records the UNIX timestamp (in seconds) of the client's
	// most recent poll. It is used to enforce the polling interval.
	LastPolledAt int64 `json:"last_polled_at,omitzero"`
}

// SessionStore abstracts the persistence layer for ephemeral authorization
// artifacts.
//
// Implementations must handle the lifecycle of authorization codes and
// refresh tokens. These artifacts usually have a limited TTL.
//
// All artifacts are keyed by their [Digest]; the [Server] hashes plaintext
// values before every store interaction. Implementations therefore never
// handle bearer secrets and can persist digests directly as primary keys.
type SessionStore interface {
	// GetAuthCode retrieves an authorization code by its digest.
	//
	// If found, it must return the data and nil.
	// If not found or expired, it must return an empty value and nil.
	// It should return an error only if the storage lookup fails.
	GetAuthCode(ctx context.Context, code Digest) (AuthCode, error)
	// CreateAuthCode stores a new authorization code.
	//
	// It should return an error only if the persistence operation fails.
	CreateAuthCode(ctx context.Context, data AuthCode) error
	// DeleteAuthCode removes an authorization code and reports whether it
	// was present. The [Server] relies on the returned flag to enforce
	// single use under concurrent redemption attempts, so implementations
	// must delete and report atomically (e.g., SQL "DELETE ... RETURNING"
	// or a Redis DEL count).
	//
	// It should return an error only if the removal operation fails.
	DeleteAuthCode(ctx context.Context, code Digest) (bool, error)
	// GetRefreshToken retrieves a refresh token by its digest.
	//
	// If found, it must return the data and nil.
	// If not found or expired, it must return an empty value and nil.
	// It should return an error only if the storage lookup fails.
	GetRefreshToken(ctx context.Context, token Digest) (RefreshToken, error)
	// CreateRefreshToken stores a new refresh token.
	//
	// It should return an error only if the persistence operation fails.
	CreateRefreshToken(ctx context.Context, data RefreshToken) error
	// DeleteRefreshToken removes a refresh token (e.g., during revocation or
	// rotation) and reports whether it was present. Like [DeleteAuthCode],
	// the deletion and the report must be atomic so that concurrent rotation
	// attempts cannot both succeed.
	//
	// It should return an error only if the removal operation fails.
	DeleteRefreshToken(ctx context.Context, token Digest) (bool, error)
	// GetDeviceCode retrieves a device code by its digest.
	//
	// If found, it must return the data and nil.
	// If not found, it must return an empty value and nil.
	// It should return an error only if the storage lookup fails.
	GetDeviceCode(ctx context.Context, code Digest) (DeviceCode, error)
	// GetDeviceCodeByUserCode retrieves a device code by the digest of its
	// associated user code. It is used by the verification endpoint where the
	// resource owner enters the user code displayed on the device.
	//
	// If found, it must return the data and nil.
	// If not found, it must return an empty value and nil.
	// It should return an error only if the storage lookup fails.
	GetDeviceCodeByUserCode(
		ctx context.Context,
		userCode Digest,
	) (DeviceCode, error)
	// CreateDeviceCode stores a new device code.
	//
	// It should return an error only if the persistence operation fails.
	CreateDeviceCode(ctx context.Context, data DeviceCode) error
	// UpdateDeviceCode replaces the stored state of a device code, keyed by
	// [DeviceCode.DeviceCode]. It is used to record status transitions
	// performed by the verification endpoint.
	//
	// It should return an error only if the persistence operation fails.
	UpdateDeviceCode(ctx context.Context, data DeviceCode) error
	// TouchDeviceCode records a client polling attempt by updating only
	// [DeviceCode.LastPolledAt] for the given code. It is deliberately
	// separate from [UpdateDeviceCode] so that concurrent polling can never
	// overwrite a status transition performed by the verification endpoint.
	// Touching an absent code is a no-op.
	//
	// It should return an error only if the persistence operation fails.
	TouchDeviceCode(ctx context.Context, code Digest, lastPolledAt int64) error
	// DeleteDeviceCode removes a device code by its digest and reports
	// whether it was present. Like [DeleteAuthCode], the deletion and the
	// report must be atomic so that concurrent redemption attempts cannot
	// both succeed.
	//
	// It should return an error only if the removal operation fails.
	DeleteDeviceCode(ctx context.Context, code Digest) (bool, error)
}

const (
	// ErrorCodeAccessDenied indicates user or server denied the request.
	ErrorCodeAccessDenied = "access_denied"
	// ErrorCodeInvalidClient indicates client authentication failed.
	ErrorCodeInvalidClient = "invalid_client"
	// ErrorCodeInvalidGrant indicates provided grant is invalid or expired.
	ErrorCodeInvalidGrant = "invalid_grant"
	// ErrorCodeInvalidRequest indicates request is missing a parameter.
	ErrorCodeInvalidRequest = "invalid_request"
	// ErrorCodeInvalidScope indicates requested scope is invalid.
	ErrorCodeInvalidScope = "invalid_scope"
	// ErrorCodeServerError indicates an internal server error occurred.
	ErrorCodeServerError = "server_error"
	// ErrorCodeTemporarilyUnavailable signals the server is overloaded.
	ErrorCodeTemporarilyUnavailable = "temporarily_unavailable"
	// ErrorCodeUnauthorizedClient indicates client is not authorized for grant.
	ErrorCodeUnauthorizedClient = "unauthorized_client"
	// ErrorCodeUnsupportedGrantType indicates grant type is not supported.
	ErrorCodeUnsupportedGrantType = "unsupported_grant_type"
	// ErrorCodeUnsupportedResponseType indicates response type is not
	// supported.
	ErrorCodeUnsupportedResponseType = "unsupported_response_type"
	// ErrorCodeAuthorizationPending indicates the user hasn't authorized yet.
	ErrorCodeAuthorizationPending = "authorization_pending"
	// ErrorCodeSlowDown indicates the client is polling too fast.
	ErrorCodeSlowDown = "slow_down"
	// ErrorCodeExpiredToken indicates the device code has expired.
	ErrorCodeExpiredToken = "expired_token"
)

// Error represents an RFC 6749 compliant error response.
type Error struct {
	// Status is the HTTP status code (e.g., 400, 401) to send when returning
	// this error.
	Status int `json:"-"`
	// Code is the machine-readable error identifier (e.g., "invalid_grant").
	Code string `json:"error"`
	// Description is an optional human-readable explanation providing
	// additional context for developers.
	Description string `json:"error_description,omitempty"`
	// URI is an optional link to a web page providing further information about
	// the error type.
	URI string `json:"error_uri,omitempty"`
	// ID is a trace identifier for the specific occurrence of the error.
	// This field is not part of the specification.
	ID string `json:"error_id,omitempty"`
	// Cause is the underlying error that triggered this one. It is logged
	// when the response is written, but never serialized, so it may carry
	// internal detail that must not reach the client.
	Cause error `json:"-"`
}

// Unwrap returns the underlying cause, if any.
func (e Error) Unwrap() error { return e.Cause }

// Error implements the standard [error] interface. It builds a formatted string
// suitable for logging.
func (e Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Proposal represents the raw input of an OAuth 2.0 grant request. It
// encapsulates the verified identity of the requesting client and the
// unvalidated parameters provided in the request body.
type Proposal struct {
	// Client is the authenticated entity making the request (read-only).
	Client Client
	// Sessions provides access to the [SessionStore] for managing
	// authorization codes and refresh tokens.
	Sessions SessionStore
	// Logger provides a context-aware logger for the grant handler.
	Logger *slog.Logger
	// Now returns the current time. Grants must use it instead of [time.Now]
	// so that temporal checks stay consistent with the server clock.
	Now func() time.Time
	// data contains the raw form values.
	data url.Values
}

// Get retrieves a grant-specific field from the HTTP request body.
// If no such field exists, an empty string is returned.
func (p *Proposal) Get(key string) string { return p.data.Get(key) }

// Has checks if a grant-specific field is present in the HTTP request body.
func (p *Proposal) Has(key string) bool { return p.data.Has(key) }

// ServerError returns an opaque internal server [Error] carrying the given
// description and cause. Grants should use it to report unexpected storage or
// infrastructure failures without leaking details to the client.
//
// The cause is not serialized. It is logged, together with a freshly assigned
// trace identifier, when the response is written; grants must not log it
// themselves.
func (p *Proposal) ServerError(desc string, cause error) *Error {
	return &Error{
		Status:      http.StatusInternalServerError,
		Code:        ErrorCodeServerError,
		Description: desc,
		Cause:       cause,
	}
}

// Issuance defines the parameters for issuing tokens after a successful grant
// authorization.
type Issuance struct {
	// Subject identifies the subject of the issued tokens. For
	// machine-to-machine requests, this field should be left as the zero UUID
	// to treat the client itself as the subject.
	Subject uuid.UUID
	// Scope represents the finalized, space-delimited list of permissions
	// granted to the client. This may be a subset of the requested scopes
	// based on server policy or user consent.
	Scope string
	// RefreshScope is the scope bound to a replacement refresh token, if one
	// is issued. It defaults to Scope when empty. The Refresh Token grant
	// sets it to the original grant scope so that a one-time narrowing of
	// the access token (RFC 6749 Section 6) does not permanently downgrade
	// the grant chain.
	RefreshScope string
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
	// expired codes, or insufficient permissions, it returns nil and an
	// [Error].
	// Other types of errors will be handled as unexpected failures.
	Authorize(ctx context.Context, pro *Proposal) (*Issuance, error)
}

// Claimant represents a user identity verified by an external provider.
type Claimant struct {
	// Subject is the unique identifier of the user at the external provider.
	Subject string `json:"sub"`
	// Email is the user's primary email address.
	Email string `json:"email,omitempty"`
	// EmailVerified indicates whether the email address has been verified.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Name is the user's full name.
	Name string `json:"name,omitempty"`
	// Picture is the URL of the user's profile picture.
	Picture string `json:"picture,omitempty"`
}

// IdentityProvider defines the contract for external social authentication
// providers (e.g., Google, GitHub, Apple).
//
// Implementations are responsible for defining the provider-specific OAuth 2.0
// or OIDC flows. The core [Server] manages CSRF protection (state generation
// and validation) and the final local session creation, allowing
// implementations to focus purely on the external exchange.
type IdentityProvider interface {
	// AuthURL generates the authorization URL to redirect the user-agent.
	//
	// Implementations must append the provided state string to the URL's
	// query parameters (e.g., `?state=...`). The redirect URI should point
	// to the server's registered ExternalCallback endpoint.
	AuthURL(ctx context.Context, state string) (string, error)
	// Exchange handles the callback request and returns the external
	// identity information.
	//
	// Implementations should extract the authorization code from the request
	// and exchange it securely via the external provider's API. Note that the
	// core [Server] already validates the state parameter against a secure
	// cookie prior to calling this method, so implementations do not need to
	// perform additional CSRF checks.
	Exchange(ctx context.Context, req *http.Request) (Claimant, error)
}

// TokenResponse outlines the payload returned after a successful token grant.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitzero"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	// IDToken carries the OpenID Connect ID token (OIDC Core Section
	// 3.1.3.3). This server does not issue ID tokens yet; the field is
	// populated by external OIDC providers and consumed when this package
	// acts as a client during social login exchanges.
	IDToken string `json:"id_token,omitempty"`
}

// DeviceAuthorizationResponse outlines the payload returned from the device
// authorization endpoint.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval,omitempty"`
}

// IntrospectionResponse outlines the RFC 7662 compliant JSON payload returned
// from the token introspection endpoint. All timestamps are UNIX epoch
// integers in seconds.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Jti       string   `json:"jti,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Iat       int64    `json:"iat,omitzero"`
	Exp       int64    `json:"exp,omitzero"`
	Nbf       int64    `json:"nbf,omitzero"`
}

// LoginRequest represents the payload for the resource owner login endpoint.
//
// It is consumed by [Provider.Login] to authenticate a resource owner and
// initiate a secure session via the [SubjectStore.Authenticate] method.
type LoginRequest struct {
	// Username is the unique identifier (e.g., an email address or handle)
	// used by the resource owner to authenticate. This value is passed to
	// [SubjectStore.Authenticate] to resolve the [Subject].
	Username string `json:"username"`
	// Password is the secret credential provided by the resource owner.
	// It is used to verify the identity of the user during the login process.
	Password string `json:"password"`
}

// Validate implements the [valid.Validatable] interface.
func (r *LoginRequest) Validate(v *valid.Validator) {
	v.NotEmpty("username", r.Username)
	v.NotEmpty("password", r.Password)
}

var _ valid.Validatable = (*LoginRequest)(nil)

const (
	// DeviceVerificationApprove signals that the resource owner approves the
	// pending device authorization request.
	DeviceVerificationApprove = "approve"
	// DeviceVerificationDeny signals that the resource owner rejects the
	// pending device authorization request.
	DeviceVerificationDeny = "deny"
)

// DeviceVerificationRequest represents the payload for the device
// verification endpoint (RFC 8628 Section 3.3).
//
// It is consumed by [Server.DeviceVerify] to let an authenticated resource
// owner approve or deny a pending device authorization request identified by
// its user code.
type DeviceVerificationRequest struct {
	// UserCode is the code displayed on the device, entered by the resource
	// owner. Case and embedded whitespace are ignored.
	UserCode string `json:"user_code"`
	// Action is either [DeviceVerificationApprove] or
	// [DeviceVerificationDeny].
	Action string `json:"action"`
}

// Validate implements the [valid.Validatable] interface.
func (r *DeviceVerificationRequest) Validate(v *valid.Validator) {
	v.NotEmpty("user_code", r.UserCode)
	v.Whitelist(
		"action",
		r.Action,
		DeviceVerificationApprove,
		DeviceVerificationDeny,
	)
}

var _ valid.Validatable = (*DeviceVerificationRequest)(nil)

// Path constants define the specific endpoints managed by the [Server].
const (
	PathAuthorize           = "/authorize"
	PathDeviceAuthorization = "/device_authorization"
	PathDeviceVerify        = "/device"
	PathExternalCallback    = "/callback/{provider}"
	PathExternalLogin       = "/login/{provider}"
	PathIntrospect          = "/introspect"
	PathKeySet              = "/jwks.json"
	PathLogin               = "/login"
	PathLogout              = "/logout"
	PathRevoke              = "/revoke"
	PathToken               = "/token"
	PathWellKnown           = "/.well-known/oauth-authorization-server"
)

// AuthorizationServerMetadata represents the OAuth 2.0 Authorization Server
// Metadata payload (RFC 8414).
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	KeySetURI                         string   `json:"jwks_uri,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

// VerifyRedirectURI checks a URI against a list of wildcard patterns.
//
// Patterns support the '*' wildcard for matching segments. For example:
//   - "https://*.deep.rent/*" matches "https://app.deep.rent/callback"
//   - "https://deep.rent/login?*" matches "https://deep.rent/login?state=xyz"
//   - "http://localhost:*" matches "http://localhost:3000"
//   - "https://deep.rent/auth" matches only that exact URI
//
// Per OAuth 2.0 specifications, URIs containing fragments (e.g., #token)
// are strictly rejected. Query parameters must match the pattern exactly
// unless a wildcard is provided, preventing unauthorized parameter injection.
//
// This function is particularly helpful for implementing the [Client]
// interface.
func VerifyRedirectURI(uri string, whitelist []string) bool {
	for _, p := range whitelist {
		if matchRedirectURI(uri, p) {
			return true
		}
	}
	return false
}

// matchRedirectURI parses the incoming URI and a given pattern, validating
// that the URI's scheme, host, port, path, and query parameters safely conform
// to the pattern's rules. It strictly isolates port wildcards (e.g., ":*")
// to prevent string corruption and rejects any incoming URIs containing
// fragments.
func matchRedirectURI(uri, pattern string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	// OAuth 2.0 specifications forbid fragments in redirect URIs.
	if u.Fragment != "" {
		return false
	}

	// Dynamically isolate the host block to safely replace :* without
	// corrupting
	// query parameters or paths.
	end := strings.Index(pattern, "://")
	if end == -1 {
		end = 0
	} else {
		end += 3
	}

	start := strings.Index(pattern[end:], "/")
	if start == -1 {
		start = len(pattern)
	} else {
		start += end
	}

	wildcardPort := false
	parsePattern := pattern

	if j := strings.LastIndex(pattern[:start], ":*"); j != -1 {
		wildcardPort = true
		parsePattern = pattern[:j] + ":0" + pattern[start:]
	}

	p, err := url.Parse(parsePattern)
	if err != nil {
		return false
	}

	if u.Scheme != p.Scheme {
		return false
	}

	if !matchSegment(u.Hostname(), p.Hostname()) {
		return false
	}

	if !wildcardPort && u.Port() != p.Port() {
		return false
	}

	if !matchSegment(u.Path, p.Path) {
		return false
	}

	// Strict query matching logic to prevent parameter injection bypasses.
	if !matchSegment(u.RawQuery, p.RawQuery) {
		return false
	}

	return true
}

// matchSegment evaluates whether a string satisfies a wildcard pattern.
//
// If the pattern lacks asterisks, it executes a strict equality check.
// Otherwise, it splits the pattern by '*' and sequentially verifies that the
// input string contains each substring in order, ensuring correct prefix and
// suffix placement.
func matchSegment(s, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return s == pattern
	}

	parts := strings.Split(pattern, "*")

	if !strings.HasPrefix(s, parts[0]) {
		return false
	}

	rem := s[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		if i == len(parts)-1 {
			return strings.HasSuffix(rem, parts[i])
		}
		j := strings.Index(rem, parts[i])
		if j == -1 {
			return false
		}
		rem = rem[j+len(parts[i]):]
	}

	return true
}

// TokenGeneratorFn produces opaque, high-entropy artifact strings (session
// keys, authorization codes, refresh tokens, device codes, user codes, and
// state parameters). The default implementations can be overridden per
// artifact via the corresponding [Option] values.
type TokenGeneratorFn func(context.Context) (string, error)

// GenerateSessionKey returns a random 43-character, base64url-encoded string
// for use as a session key.
func GenerateSessionKey(context.Context) (string, error) {
	return opaque()
}

// GenerateAuthCode returns a random 43-character, base64url-encoded string
// for use as an authorization code.
func GenerateAuthCode(context.Context) (string, error) {
	return opaque()
}

// GenerateRefreshToken returns a random 43-character, base64url-encoded string
// for use as a refresh token.
func GenerateRefreshToken(context.Context) (string, error) {
	return opaque()
}

// GenerateDeviceCode returns a random 43-character, base64url-encoded string
// for use as a device code.
func GenerateDeviceCode(context.Context) (string, error) {
	return opaque()
}

// GenerateState returns a random 43-character, base64url-encoded string
// for use as a state parameter.
func GenerateState(context.Context) (string, error) {
	return opaque()
}

// userCodeAlphabet is the character set for user codes, as recommended by
// RFC 8628 Section 6.1: uppercase consonants only, avoiding vowels (to
// prevent accidental words) and visually ambiguous characters.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// GenerateUserCode generates a random 9-character string of the form XXXX-XXXX
// for use as a user code. Characters are drawn uniformly from
// [userCodeAlphabet].
func GenerateUserCode(context.Context) (string, error) {
	// Rejection sampling keeps the character distribution uniform:
	// only bytes below the largest multiple of len(alphabet) are used.
	limit := byte(256 - 256%len(userCodeAlphabet))

	var chars [8]byte
	buf := make([]byte, 16)
	i := 0
	for i < len(chars) {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < limit {
				chars[i] = userCodeAlphabet[int(b)%len(userCodeAlphabet)]
				if i++; i == len(chars) {
					break
				}
			}
		}
	}
	return string(chars[:4]) + "-" + string(chars[4:]), nil
}

// opaque generates a high-entropy, base64url-encoded string suitable for
// use as a secure token. It always contains 43 characters.
func opaque() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
