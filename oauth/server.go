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
	"time"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/vault"
)

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
			ClientID: claims.Azp,
			Scope:    claims.Scope.String(),
			Jti:      claims.Jti,
			Iss:      claims.Iss,
			Aud:      claims.Aud,
			Sub:      claims.Sub,
			Iat:      UnixTime{claims.IssuedAt()},
			Exp:      UnixTime{claims.ExpiresAt()},
			Nbf:      UnixTime{claims.NotBefore()},
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
