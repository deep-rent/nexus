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
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/dat/valid"
	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/internal/limit"
	"github.com/deep-rent/nexus/sec/iam/oauth/pkce"
	"github.com/deep-rent/nexus/sec/jose/jwt"
	"github.com/deep-rent/nexus/sec/nonce"
	"github.com/deep-rent/nexus/sec/vault"
	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
)

// Token generation defaults. Every opaque bearer artifact is drawn from one
// [nonce.Generator]; user codes are drawn from one [nonce.Sampler].
const (
	// NonceSize is the byte length of an opaque bearer artifact. 32 bytes yield
	// 256 bits of entropy and a 43-character base64url string.
	NonceSize = 32

	// userCodeAlphabet is the character set for user codes, as recommended by
	// RFC 8628 Section 6.1: uppercase consonants only, avoiding vowels (to
	// prevent accidental words) and visually ambiguous characters.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

	// userCodeLength is the number of characters sampled for a user code.
	// Including the hyphen separator, the user code will be 9 characters long
	// in total.
	userCodeLength = 8
)

// userCodeRegex matches a user code rendered in the canonical XXXX-XXXX format.
// Matching expects uppercase letters, a hyphen separator and no whitespace.
var userCodeRegex = regexp.MustCompile(
	`^[` + userCodeAlphabet + `]{4}-[` + userCodeAlphabet + `]{4}$`,
)

// Path constants define the endpoints managed by the [Server].
const (
	PathAuthorize           = "/authorize"
	PathDeviceAuthorization = "/device_authorization"
	PathDeviceVerify        = "/device"
	PathIntrospect          = "/introspect"
	PathKeySet              = "/jwks.json"
	PathRevoke              = "/revoke"
	PathToken               = "/token"
	PathWellKnown           = "/.well-known/oauth-authorization-server"
)

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
	v.Match("user_code", r.UserCode, userCodeRegex)
	v.Whitelist(
		"action",
		r.Action,
		DeviceVerificationApprove,
		DeviceVerificationDeny,
	)
}

var _ valid.Validatable = (*DeviceVerificationRequest)(nil)

// Owner is the authenticated resource owner as the token machinery sees it:
// just enough identity to mint claims and bind artifacts. The IAM server's
// Subject satisfies it structurally.
type Owner interface {
	// ID returns the unique identifier for the owner.
	ID() uuid.UUID
	// Roles returns the list of roles assigned to the owner, used to
	// populate the roles claim in access tokens.
	Roles() []string
}

// SessionResolver authenticates the resource owner behind a request — for
// this server, typically via a session cookie established by a login system
// it knows nothing about.
//
// It must return nil, nil when no valid session exists, and an error only
// when the underlying lookup fails. The authorization and device
// verification endpoints consult it.
type SessionResolver func(e *router.Exchange) (Owner, error)

// OwnerResolver resolves an owner by their unique ID, used by the token
// endpoint to populate the claims of delegated tokens.
//
// It must return nil, nil when no such owner exists, and an error only when
// the underlying lookup fails.
type OwnerResolver func(ctx context.Context, id uuid.UUID) (Owner, error)

// Server implements the endpoints of an OAuth 2.0 authorization server: the
// token, authorization, introspection, revocation, and device authorization
// machinery, together with the RFC 8414 metadata and JWKS documents.
//
// It is deliberately login-agnostic: everything it knows about resource
// owners arrives through the [SessionResolver] and [OwnerResolver] seams, so
// it can stand alone in a machine-to-machine deployment or be composed with
// a login system such as the IAM server. Create instances with [NewServer]
// and attach them to a router via [Server.Mount].
type Server struct {
	grants               map[GrantType]Grant
	vault                vault.Vault
	clients              ClientStore
	tokens               TokenStores
	sessions             SessionResolver
	owners               OwnerResolver
	introspector         jwt.Verifier[*auth.Claims]
	issuer               string
	realm                string
	verificationURI      string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	authCodeLifetime     time.Duration
	deviceCodeLifetime   time.Duration
	devicePollInterval   time.Duration
	nonceSource          nonce.Source
	nonce                *nonce.Generator
	userCodes            *nonce.Sampler
	hasher               *digest.Hasher
	limit                limit.Limiter
	logger               *log.Logger
	now                  clock.Clock
}

// NewServer assembles a [Server] from the given configuration and options.
//
// It panics if a required [ServerConfig] field is missing, or if a
// registered grant depends on a resolver that was not provided. Server
// construction happens once at startup, so misconfiguration is a programmer
// error rather than a recoverable runtime condition.
func NewServer(cfg ServerConfig, opts ...ServerOption) *Server {
	switch {
	case cfg.Vault == nil:
		panic("vault is required")
	case cfg.Clients == nil:
		panic("clients is required")
	case cfg.Tokens.AuthCodes == nil:
		panic("auth code store is required")
	case cfg.Tokens.RefreshTokens == nil:
		panic("refresh token store is required")
	case cfg.Issuer == "":
		panic("issuer is required")
	}

	if _, err := url.Parse(cfg.Issuer); err != nil {
		panic("issuer is not a valid URL: " + err.Error())
	}
	if cfg.VerificationURI != "" {
		if _, err := url.Parse(cfg.VerificationURI); err != nil {
			panic("verification URI is not a valid URL: " + err.Error())
		}
		if cfg.Tokens.DeviceCodes == nil {
			panic("verification URI requires a device code store")
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.Discard()
	}

	s := &Server{
		grants:   make(map[GrantType]Grant),
		vault:    cfg.Vault,
		clients:  cfg.Clients,
		tokens:   cfg.Tokens,
		sessions: cfg.Sessions,
		owners:   cfg.Owners,
		issuer:   cfg.Issuer,
		realm:    cmp.Or(cfg.Realm, DefaultRealm),
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
		verificationURI: cfg.VerificationURI,
		limit: limit.New(
			cfg.Throttle,
			cmp.Or(cfg.ThrottlePenalty, DefaultThrottlePenalty),
		),
		hasher: digest.DefaultHasher,
		logger: logger,
		now:    clock.System,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Grants that name a resource owner need the owner resolver to mint
	// claims; the session-bound endpoints need the session resolver.
	delegated := false
	for gt := range s.grants {
		if gt != GrantTypeClientCredentials {
			delegated = true
		}
	}
	if delegated && s.owners == nil {
		panic(
			"ServerConfig.Owners is required for grants that name a " +
				"resource owner",
		)
	}
	if (s.Supports(GrantTypeAuthorizationCode) || s.verificationURI != "") &&
		s.sessions == nil {
		panic(
			"ServerConfig.Sessions is required for the authorization and " +
				"device verification endpoints",
		)
	}

	// Every opaque bearer artifact is drawn from one generator, and every
	// user code from one sampler, both fed by the configured source
	// (crypto/rand by default). They are built after the options so they
	// observe the final source.
	s.nonce = nonce.NewGenerator(s.nonceSource, NonceSize)
	s.userCodes = nonce.NewSampler(
		s.nonceSource,
		userCodeAlphabet,
		userCodeLength,
	)

	s.introspector = jwt.NewVerifier[*auth.Claims](
		s.vault.Keys(),
		jwt.WithIssuers(s.issuer),
		jwt.WithClock(s.now),
	)

	return s
}

// Supports checks whether the given grant type has been registered.
func (s *Server) Supports(grant GrantType) bool {
	_, ok := s.grants[grant]
	return ok
}

// Mount registers the server's endpoints below the given path prefix: the
// well-known metadata and JWKS documents, the authorization, token,
// introspection, and revocation endpoints, and — when a verification URI is
// configured — the device authorization endpoints.
//
// When [ServerConfig.Throttle] is set, every endpoint that verifies a
// credential is wrapped in the throttle middleware.
func (s *Server) Mount(r *router.Router, prefix string) {
	// guarded protects endpoints that accept credential guesses.
	var guarded []router.Middleware
	if s.limit.Enabled() {
		guarded = append(guarded, s.limit.Middleware())
	}

	wellKnown := s.WellKnown(prefix)
	r.Handle(http.MethodGet+" "+prefix+PathWellKnown, wellKnown)

	// RFC 8414 Section 3: clients derive the metadata URL by inserting the
	// well-known path between the issuer's authority and path components.
	// Serve that location too whenever it differs from the prefixed route.
	if u, err := url.Parse(s.issuer); err == nil {
		root := PathWellKnown + strings.TrimSuffix(u.Path, "/")
		if root != prefix+PathWellKnown {
			r.Handle(http.MethodGet+" "+root, wellKnown)
		}
	}

	r.Handle(http.MethodGet+" "+prefix+PathKeySet, vault.Handler(s.vault))

	r.HandleFunc(http.MethodGet+" "+prefix+PathAuthorize, s.Authorize)
	r.HandleFunc(http.MethodPost+" "+prefix+PathAuthorize, s.Authorize)
	r.HandleFunc(http.MethodPost+" "+prefix+PathToken, s.Token, guarded...)
	r.HandleFunc(http.MethodPost+" "+prefix+PathRevoke, s.Revoke, guarded...)
	r.HandleFunc(
		http.MethodPost+" "+prefix+PathIntrospect,
		s.Introspect,
		guarded...,
	)

	if s.verificationURI != "" {
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathDeviceAuthorization,
			s.DeviceAuthorization,
			guarded...,
		)
		r.HandleFunc(
			http.MethodPost+" "+prefix+PathDeviceVerify,
			s.DeviceVerify,
			guarded...,
		)
	}
}

// WellKnown serves the OAuth 2.0 Authorization Server Metadata (RFC 8414)
// derived from the server configuration and the registered grants.
func (s *Server) WellKnown(prefix string) router.Handler {
	base := strings.TrimSuffix(s.issuer, "/") + prefix

	meta := ServerMetadata{
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

// resolveSession authenticates the resource owner behind the request via the
// configured [SessionResolver]. A server without one treats every request as
// anonymous.
func (s *Server) resolveSession(e *router.Exchange) (Owner, error) {
	if s.sessions == nil {
		return nil, nil
	}
	return s.sessions(e)
}

// digest fingerprints a bearer artifact with the server's configured hasher;
// see [WithHasher].
func (s *Server) digest(value string) Digest {
	return Digest(s.hasher.String(value))
}

// challenge sets the WWW-Authenticate header to signal to the client that
// HTTP Basic authentication is required, as mandated by RFC 6749 Section 5.2
// for client authentication failures.
func (s *Server) challenge(e *router.Exchange) {
	e.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", s.realm))
}

// authenticate verifies the requesting client's identity (HTTP Basic or POST
// parameters) and assembles the [Proposal] handed to grants.
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
		if data.Has("client_secret") {
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
		// Many client libraries redundantly include client_id in the body
		// alongside HTTP Basic authentication; tolerate it as long as it
		// names the same client.
		if id := data.Get("client_id"); id != "" && id != clientID {
			return nil, &Error{
				Status:      http.StatusBadRequest,
				Code:        ErrorCodeInvalidRequest,
				Description: "mismatched client id",
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

	// Repeated guesses against one client identity are locked out before
	// the store is consulted, regardless of the address they arrive from.
	clientKey := limit.ScopeClient + clientID
	if s.limit.Throttled(e, clientKey) {
		// Build an OAuth-shaped rejection returned once the endpoint has
		// exhausted its throttle allowance.
		//
		// RFC 6749 defines no error code for rate limiting, so the device-flow
		// "slow_down" code (RFC 8628 Section 3.5) is reused: its semantics
		// match exactly, and clients that do not recognize it still honor the
		// 429 status and the accompanying Retry-After header.
		return nil, &Error{
			Status:      http.StatusTooManyRequests,
			Code:        ErrorCodeSlowDown,
			Description: "too many failed attempts",
		}
	}

	// deny records a failed credential attempt before returning the
	// (deliberately uniform) rejection.
	deny := func(desc string) (*Proposal, error) {
		s.limit.Penalize(clientKey, s.limit.Addr(e))
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: desc,
		}
	}

	// Client identifiers are UUIDs; a malformed value is indistinguishable
	// from an unknown client.
	id, err := uuid.Parse(clientID)
	if err != nil {
		return deny("unknown client")
	}

	client, err := s.clients.GetClient(e.Context(), id)
	if err != nil {
		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve client",
			Cause:       err,
		}
	}

	if client == nil {
		return deny("unknown client")
	}

	if clientSecret == "" && !client.Public() {
		return deny("client requires a secret")
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		return deny("invalid client secret")
	}

	// The credential is proven; drop any penalty from earlier attempts.
	s.limit.Clear(clientKey)

	return NewProposal(
		client,
		s.tokens,
		data,
		s.hasher,
		s.logger,
		s.now,
	), nil
}

// Introspect handles token introspection requests (RFC 7662).
//
// It allows authorized resource servers to query the metadata and active
// status of a given access token. The handler authenticates the client making
// the request and checks the provided token's validity against the server's
// key set. Public clients are rejected, as they could otherwise probe tokens
// they do not own.
func (s *Server) Introspect(e *router.Exchange) error {
	return s.wrap(e, s.introspect)
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
		s.logger.Debug(
			e.Context(),
			"Token verification failed during introspection",
			log.Error(err),
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
		if claims.Azp != "" {
			res.ClientID = claims.Azp
		}
		res.Sub = claims.Sub
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
// identity, redirect URI, and requested scopes. If the resource owner has an
// active session (resolved via the configured [SessionResolver]), it
// generates an authorization code and redirects the user-agent back to the
// client's redirect URI.
func (s *Server) Authorize(e *router.Exchange) error {
	return s.wrap(e, s.authorize)
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
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve client",
			Cause:       err,
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
	case scope != "" && !CanUseScope(client, scope):
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

	// Authenticate the resource owner via the configured session resolver.
	owner, err := s.resolveSession(e)
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to lookup subject",
			Cause:       err,
		}
	}

	if owner == nil {
		return fail(
			ErrorCodeAccessDenied,
			"resource owner is not authenticated",
		)
	}

	code, err := s.nonce.Draw(e.Context())
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate authorization code",
			Cause:       err,
		}
	}

	if err := s.tokens.AuthCodes.Create(
		e.Context(),
		AuthCode{
			Code:                s.digest(code),
			ClientID:            client.ID(),
			RedirectURI:         redirectURI,
			Scope:               scope,
			SubjectID:           owner.ID(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ExpiresAt:           s.now().Add(s.authCodeLifetime).Unix(),
		},
	); err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to store authorization code",
			Cause:       err,
		}
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
	return s.wrap(e, s.token)
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

	now := s.now()
	clientID := pro.Client.ID()

	claims := &auth.Claims{
		Azp:   clientID.String(),
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
		claims.Sub = clientID.String() // The subject is the client itself
	} else if owner, err := s.owners(
		e.Context(),
		iss.Subject,
	); err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve subject",
			Cause:       err,
		}
	} else if owner != nil {
		claims.Sub = owner.ID().String()
		claims.Roles = owner.Roles()
	} else {
		s.logger.Error(
			e.Context(),
			"Subject not found for claims",
			log.UUID("subject", iss.Subject),
		)

		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "subject no longer available",
		}
	}

	key := s.vault.Next()
	if key == nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "unable to obtain signing key",
			Cause:       errors.New("vault returned no signing key"),
		}
	}

	token, err := jwt.Sign(e.Context(), key, claims)
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to mint access token",
			Cause:       err,
		}
	}

	res := TokenResponse{
		AccessToken: string(token),
		TokenType:   auth.Scheme,
		ExpiresIn:   int64(s.accessTokenLifetime.Seconds()),
		Scope:       iss.Scope,
	}

	if iss.Refreshable &&
		s.Supports(GrantTypeRefreshToken) &&
		pro.Client.CanUseGrant(GrantTypeRefreshToken) {
		token, err := s.nonce.Draw(e.Context())
		if err != nil {
			return &Error{
				Status:      http.StatusInternalServerError,
				Code:        ErrorCodeServerError,
				Description: "failed to generate refresh token",
				Cause:       err,
			}
		}

		if err := s.tokens.RefreshTokens.Create(e.Context(), RefreshToken{
			Token:     s.digest(token),
			ClientID:  clientID,
			SubjectID: iss.Subject,
			Scope:     cmp.Or(iss.RefreshScope, iss.Scope),
			ExpiresAt: now.Add(s.refreshTokenLifetime).Unix(),
		}); err != nil {
			return &Error{
				Status:      http.StatusInternalServerError,
				Code:        ErrorCodeServerError,
				Description: "failed to save refresh token",
				Cause:       err,
			}
		}

		res.RefreshToken = token
	}

	return e.JSON(http.StatusOK, res)
}

// Revoke handles token revocation requests per RFC 7009.
//
// It allows clients to signal that a previously obtained refresh token is no
// longer needed. The handler authenticates the client and, if the provided
// token is a valid refresh token belonging to that client, removes it from
// [TokenStores.RefreshTokens].
func (s *Server) Revoke(e *router.Exchange) error {
	return s.wrap(e, s.revoke)
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

	// The store only ever sees the digest of the token.
	digest := s.digest(token)

	// Validate token ownership before revocation per RFC 7009 Section 2.1
	r, found, err := s.tokens.RefreshTokens.Get(e.Context(), digest)
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve token",
			Cause:       err,
		}
	}
	if !found || r.ClientID != pro.Client.ID() {
		// Token not found or belongs to another client. Return 200 OK.
		e.Status(http.StatusOK)
		return nil
	}

	if _, err := s.tokens.RefreshTokens.Delete(
		e.Context(),
		digest,
	); err != nil {
		s.logger.Error(
			e.Context(),
			"Failed to delete refresh token during revocation",
			log.Error(err),
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
// Note: This endpoint requires a valid [ServerConfig.VerificationURI] to be
// provided during server initialization.
func (s *Server) DeviceAuthorization(e *router.Exchange) error {
	return s.wrap(e, s.deviceAuthorization)
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
	if scope != "" && !CanUseScope(pro.Client, scope) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	deviceCode, err := s.nonce.Draw(e.Context())
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate device code",
			Cause:       err,
		}
	}

	userCode, err := s.userCodes.Draw(e.Context())
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate user code",
			Cause:       err,
		}
	}

	// Render the user code in the canonical XXXX-XXXX format composed of two
	// dash-separated groups.
	userCode = userCode[:4] + "-" + userCode[4:]

	interval := int64(s.devicePollInterval.Seconds())

	// The user code is digested in its canonical form so that the lookup in
	// DeviceVerify (which normalizes user input the same way) always
	// matches, regardless of the generator's output format.
	if err := s.tokens.DeviceCodes.Create(e.Context(), DeviceCode{
		DeviceCode: s.digest(deviceCode),
		UserCode:   s.digest(userCode),
		ClientID:   pro.Client.ID(),
		Scope:      scope,
		Status:     DeviceCodeStatusPending,
		ExpiresAt:  s.now().Add(s.deviceCodeLifetime).Unix(),
		Interval:   interval,
	}); err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to store device code",
			Cause:       err,
		}
	}

	// ServerConfig.VerificationURI is validated during construction, so
	// parsing cannot fail here. Building the complete URI through url.Values
	// keeps it correct even when the configured URI already carries a query.
	complete, err := url.Parse(s.verificationURI)
	if err != nil {
		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "invalid verification URI",
			Cause:       err,
		}
	}
	q := complete.Query()
	q.Set("user_code", userCode)
	complete.RawQuery = q.Encode()

	res := DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         s.verificationURI,
		VerificationURIComplete: complete.String(),
		ExpiresIn:               int64(s.deviceCodeLifetime.Seconds()),
		Interval:                interval,
	}

	return e.JSON(http.StatusOK, res)
}

// DeviceVerify lets an authenticated resource owner approve or deny a
// pending device authorization request (RFC 8628 Section 3.3).
//
// The resource owner is identified via the configured [SessionResolver]. The
// request payload is a [DeviceVerificationRequest] carrying the user code
// displayed on the device and the desired action.
//
// Note that the user code is not canonicalized, it is matched as-is.
func (s *Server) DeviceVerify(e *router.Exchange) error {
	owner, err := s.resolveSession(e)
	if err != nil {
		return router.ServerError("failed to lookup subject", err)
	}
	if owner == nil {
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

	// RFC 8628 Section 5.1: user codes are short enough to be guessed, so
	// the verification endpoint must be rate limited. The session holder is
	// throttled rather than the code, since an attacker guessing codes
	// controls their own session but not the codes they hit.
	subjectKey := limit.ScopeCode + owner.ID().String()
	if s.limit.Throttled(e, subjectKey) {
		return &router.Error{
			Status:      http.StatusTooManyRequests,
			Reason:      router.ReasonRateLimit,
			Description: "too many failed attempts; try again later",
		}
	}

	code, found, err := s.tokens.DeviceCodes.GetByUserCode(
		e.Context(),
		s.digest(req.UserCode),
	)
	if err != nil {
		return router.ServerError("failed to retrieve device code",
			err,
		)
	}

	if !found ||
		(code.ExpiresAt != 0 && s.now().Unix() > code.ExpiresAt) {
		s.limit.Penalize(subjectKey, s.limit.Addr(e))
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
		code.SubjectID = owner.ID()
	} else {
		code.Status = DeviceCodeStatusDenied
	}

	if err := s.tokens.DeviceCodes.Update(e.Context(), code); err != nil {
		return router.ServerError("failed to update device code",
			err,
		)
	}

	e.NoContent()

	return nil
}

// wrap executes the handler and translates any returned [Error] into an HTTP
// JSON response using the error's defined status code.
//
// This is the error boundary for the RFC 6749 error shape, and therefore the
// one place that logs it: handlers and grants return errors, they do not
// report them. Errors that are not an [Error] fall through to the router,
// which logs them the same way.
func (s *Server) wrap(
	e *router.Exchange,
	handler func(*router.Exchange) error,
) error {
	// RFC 6749 Sections 5.1 and 5.2: responses containing tokens or error
	// details must not be cached. This applies to error responses as well,
	// so the headers are set up front.
	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")

	err := handler(e)
	oerr, ok := errors.AsType[*Error](err)
	if !ok {
		return err
	}

	// A server error is the kind a client may quote back in a bug report, so
	// it always carries an identifier that can be found in the logs.
	if oerr.ID == "" && oerr.Status >= http.StatusInternalServerError {
		oerr.ID = router.ErrorID()
	}

	s.record(e, oerr)

	return e.JSON(oerr.Status, oerr)
}

// record logs a failed OAuth exchange. Server errors are reported at error
// level; the protocol errors that make up normal traffic (invalid_grant,
// invalid_client and friends) are recorded at debug level so they do not
// drown the logs.
func (s *Server) record(e *router.Exchange, oerr *Error) {
	ctx := e.Context()

	level := log.LevelDebug
	if oerr.Status >= http.StatusInternalServerError {
		level = log.LevelError
	}

	if !s.logger.Enabled(ctx, level) {
		return
	}

	attrs := []log.Arg{
		log.Int("status", oerr.Status),
		log.String("code", oerr.Code),
		log.String("path", e.Path()),
	}
	if oerr.ID != "" {
		attrs = append(attrs, log.String(log.ErrorIDKey, oerr.ID))
	}
	if oerr.Cause != nil {
		attrs = append(attrs, log.Error(oerr.Cause))
	}

	s.logger.Log(ctx, level, oerr.Description, attrs...)
}
