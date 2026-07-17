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
	"uuid"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/pkce"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/vault"
)

type Config struct {
	// TODO
}

type Server struct {
	grants               map[GrantType]Grant
	idps                 map[string]IdentityProvider
	vault                vault.Vault
	clients              ClientStore
	sessions             SessionStore
	subjects             SubjectStore
	issuer               string
	sessionCookieName    string
	stateCookieName      string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	authCodeLifetime     time.Duration
	deviceCodeLifetime   time.Duration
	realm                string
	loginTerminalURI     string
	loginRedirectURI     string
	generateSessionKey   TokenGeneratorFn
	generateAuthCode     TokenGeneratorFn
	generateRefreshToken TokenGeneratorFn
	generateDeviceCode   TokenGeneratorFn
	generateUserCode     TokenGeneratorFn
	generateState        TokenGeneratorFn
	verificationURI      string
	logger               *slog.Logger
	clock                func() time.Time
}

func New(cfg *Config) *Server {
	return nil // TODO
}

// Supports checks whether the given grant type has been registered.
func (s *Server) Supports(grant GrantType) bool {
	_, ok := s.grants[grant]
	return ok
}

func (s *Server) Mount(r *router.Router, prefix string) {
	r.Handle(
		http.MethodGet+" "+prefix+"/.well-known/oauth-authorization-server",
		s.WellKnown(prefix),
	)

	r.Handle(
		http.MethodGet+" "+prefix+"/jwks.json",
		vault.Handler(s.vault),
	)

	// TODO: Register other endpoints (Token, ...)
}

func (s *Server) WellKnown(prefix string) router.Handler {
	return router.HandlerFunc(func(e *router.Exchange) error {
		meta := AuthorizationServerMetadata{
			// TODO
		}
		return e.JSON(http.StatusOK, meta)
	})
}

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
		if data.Has("client_id") || data.Has("client_secret") {
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
	}

	if clientID == "" {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "missing client id",
		}
	}

	client, err := s.clients.GetClient(e.Context(), clientID)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Client lookup failed",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve client",
			ID:          id,
		}
	}

	if client == nil {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "unknown client",
		}
	}

	if clientSecret == "" && !client.Public() {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "client requires a secret",
		}
	}

	if clientSecret != "" && !client.VerifySecret(clientSecret) {
		s.challenge(e)
		return nil, &Error{
			Status:      http.StatusUnauthorized,
			Code:        ErrorCodeInvalidClient,
			Description: "invalid client secret",
		}
	}

	return &Proposal{
		Client:   client,
		Sessions: s.sessions,
		Logger:   s.logger,
		data:     data,
	}, nil
}

// challenge sets the WWW-Authenticate header to signal to the client that
// HTTP Basic authentication is required, as mandated by RFC 6749 Section 5.2
// for client authentication failures.
func (s *Server) challenge(e *router.Exchange) {
	e.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", s.realm))
}

// Introspect handles token introspection requests (RFC 7662).
//
// It allows authorized resource servers to query the metadata and active status
// of a given access token. The handler authenticates the client making the
// request and uses the configured [jwt.Verifier] to check the provided token's
// validity.
func (s *Server) Introspect(e *router.Exchange) error {
	return wrap(e, s.introspect)
}

// introspect contains the logic for the token introspection endpoint.
func (s *Server) introspect(e *router.Exchange) error {
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

	var res IntrospectionResponse

	v := jwt.NewVerifier[*auth.Claims](
		s.vault.Keys(),
		jwt.WithIssuers(s.issuer),
		jwt.WithClock(s.clock),
	)

	if claims, err := v.Verify([]byte(token)); err != nil {
		s.logger.DebugContext(
			e.Context(),
			"Token verification failed during introspection",
			slog.Any("error", err),
		)
	} else {
		res = IntrospectionResponse{
			Active:   true,
			ClientID: claims.Azp.String(),
			Scope:    claims.Scope.String(),
			Jti:      claims.Jti,
			Iss:      claims.Iss,
			Aud:      claims.Aud,
			Sub:      claims.Sub.String(),
			Iat:      UnixTime{claims.IssuedAt()},
			Exp:      UnixTime{claims.ExpiresAt()},
			Nbf:      UnixTime{claims.NotBefore()},
		}
	}

	return e.JSON(http.StatusOK, res)
}

// Authorize handles requests to the authorization endpoint (RFC 6749
// Section 3.1).
//
// It supports both GET and POST requests. The handler validates the client
// identity, redirect URI, and requested scopes. If the resource owner
// has an active session (previously established via [Server.Login]), it
// generates an authorization code and redirects the user-agent back to
// the client's redirect URI.
func (s *Server) Authorize(e *router.Exchange) error {
	return wrap(e, s.authorize)
}

// authorize contains the logic for the authorization endpoint.
func (s *Server) authorize(e *router.Exchange) error {
	data := e.Query()

	clientID := data.Get("client_id")
	if clientID == "" {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing client id",
		}
	}

	client, err := s.clients.GetClient(e.Context(), clientID)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve client",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve client",
			ID:          id,
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
	cookie, err := e.Cookie(s.sessionCookieName)
	if err != nil || cookie.Value == "" {
		return fail(
			ErrorCodeAccessDenied,
			"session cookie not found or empty",
		)
	}

	key := cookie.Value
	sub, err := s.subjects.GetSubjectBySession(e.Context(), key)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to lookup subject by session",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to lookup subject",
			ID:          id,
		}
	}

	if sub == nil {
		return fail(
			ErrorCodeAccessDenied,
			"unknown subject",
		)
	}

	code, err := s.generateAuthCode(e.Context())
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to generate authorization code",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate authorization code",
			ID:          id,
		}
	}

	if err := s.sessions.CreateAuthCode(
		e.Context(),
		AuthCode{
			Code:                code,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			SubjectID:           sub.ID(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ExpiresAt:           time.Now().Add(s.authCodeLifetime),
		},
	); err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to store authorization code",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to store authorization code",
			ID:          id,
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
	return wrap(e, s.token)
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

	if !pro.Client.CanUseGrant(grantType) {
		return &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "grant type not allowed",
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

	iss, err := grant.Authorize(e.Context(), pro)
	if err != nil {
		return err
	}

	clientID, err := uuid.Parse(pro.Client.ID())
	if err != nil {
		return err // TODO: The client ID should not require parsing
	}

	now := s.clock()

	claims := &auth.Claims{
		Azp:   clientID,
		Scope: strings.Fields(iss.Scope),
		Reserved: jwt.Reserved{
			Jti: uuid.New().String(),
			Iss: s.issuer,
			Aud: pro.Client.Audience(),
			Iat: now,
			Nbf: now,
			Exp: now.Add(s.accessTokenLifetime),
		},
	}

	// Populate claims based on the context of the grant.
	if iss.Subject == "" {
		claims.Sub = clientID // The subject is the client itself
	} else if sub, err := s.subjects.GetSubject(
		e.Context(),
		iss.Subject,
	); err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve subject for claims",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve subject",
			ID:          id,
		}
	} else if sub != nil {
		id, err := uuid.Parse(sub.ID())
		if err != nil {
			return err // TODO: The subject ID should not require parsing
		}

		claims.Sub = id
		claims.Roles = sub.Roles()
	} else {
		s.logger.ErrorContext(
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

	key := s.vault.Next()
	if key == nil {
		s.logger.ErrorContext(
			e.Context(),
			"Could not obtain signing key",
		)

		// TODO: Add id

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "unable to obtain signing key",
		}
	}

	token, err := jwt.Sign(e.Context(), key, claims)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to sign access token",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to mint access token",
			ID:          id,
		}
	}

	expiresIn := uint64(s.accessTokenLifetime.Seconds())

	res := TokenResponse{
		AccessToken: string(token),
		TokenType:   auth.Scheme,
		ExpiresIn:   expiresIn,
		Scope:       iss.Scope,
	}

	if iss.Refreshable && s.Supports(GrantTypeRefreshToken) {
		token, err := s.generateRefreshToken(e.Context())
		if err != nil {
			id := router.ErrorID()

			s.logger.ErrorContext(
				e.Context(),
				"Failed to generate refresh token",
				slog.String("error_id", id),
				slog.Any("error", err),
			)

			return &Error{
				Status:      http.StatusInternalServerError,
				Code:        ErrorCodeServerError,
				Description: "failed to generate refresh token",
				ID:          id,
			}
		}

		err = s.sessions.CreateRefreshToken(e.Context(), RefreshToken{
			Token:     token,
			ClientID:  pro.Client.ID(),
			SubjectID: iss.Subject,
			Scope:     iss.Scope,
			ExpiresAt: time.Now().Add(s.refreshTokenLifetime),
		})
		if err != nil {
			id := router.ErrorID()

			s.logger.ErrorContext(
				e.Context(),
				"Failed to save refresh token",
				slog.String("error_id", id),
				slog.Any("error", err),
			)

			return &Error{
				Status:      http.StatusInternalServerError,
				Code:        ErrorCodeServerError,
				Description: "failed to save refresh token",
				ID:          id,
			}
		}

		res.RefreshToken = token
	}

	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")

	return e.JSON(http.StatusOK, res)
}

// Revoke handles token revocation requests per RFC 7009.
//
// It allows clients to signal that a previously obtained refresh token is no
// longer needed. The handler authenticates the client and, if the provided
// token is a valid refresh token belonging to that client, removes it from the
// [SessionStore].
func (s *Server) Revoke(e *router.Exchange) error {
	return wrap(e, s.revoke)
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

	// Validate token ownership before revocation per RFC 7009 Section 2.1
	r, err := s.sessions.GetRefreshToken(e.Context(), token)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to retrieve refresh token during revocation",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve token",
			ID:          id,
		}
	}
	if r.Token == "" || r.ClientID != pro.Client.ID() {
		// Token not found or belongs to another client. Return 200 OK.
		e.Status(http.StatusOK)
		return nil
	}

	if err := s.sessions.DeleteRefreshToken(e.Context(), token); err != nil {
		s.logger.ErrorContext(
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
func (s *Server) DeviceAuthorization(e *router.Exchange) error {
	return wrap(e, s.deviceAuthorization)
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

	deviceCode, err := s.generateDeviceCode(e.Context())
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to generate device code",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate device code",
			ID:          id,
		}
	}

	userCode, err := s.generateUserCode(e.Context())
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to generate user code",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to generate user code",
			ID:          id,
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

	expiresAt := time.Now().Add(s.deviceCodeLifetime)

	if err := s.sessions.CreateDeviceCode(e.Context(), DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   pro.Client.ID(),
		Scope:      scope,
		Status:     DeviceCodeStatusPending,
		ExpiresAt:  expiresAt,
	}); err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to store device code",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to store device code",
			ID:          id,
		}
	}

	res := DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.verificationURI,
		ExpiresIn:       int(s.deviceCodeLifetime.Seconds()),
		Interval:        5,
	}

	e.SetHeader("Cache-Control", "no-store")
	e.SetHeader("Pragma", "no-cache")

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
