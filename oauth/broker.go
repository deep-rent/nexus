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
	"strconv"
	"strings"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/router"
)

// Login handles the resource owner authentication and establishes a session.
//
// It expects a JSON payload with username and password. On success, it
// generates a high-entropy session key, stores it via [SubjectStore], and sets
// a secure session cookie on the user-agent.
//
// Note: When calling this endpoint from a cross-origin frontend (e.g., an SPA),
// the CORS middleware must be configured with AllowCredentials set to true,
// and AllowOrigin must not be a wildcard ("*").
func (s *Server) Login(e *router.Exchange) error {
	var cred LoginRequest
	if err := e.BindJSON(&cred); err != nil {
		return err
	}

	// Guesses are counted per account, folded to lower case so that varying
	// the capitalization cannot buy a fresh allowance.
	userKey := scopeUser + strings.ToLower(cred.Username)
	if s.throttled(e, userKey) {
		return tooManyRequests()
	}

	sub, err := s.subjects.Authenticate(
		e.Context(),
		cred.Username,
		cred.Password,
	)
	if err != nil {
		return s.internalError("failed to lookup subject", err)
	}
	if sub == nil {
		s.penalize(userKey, s.addr(e))
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      router.ReasonValidationFailed,
			Description: "invalid credentials",
		}
	}

	// The password is proven; drop any penalty from earlier attempts.
	s.clear(userKey)

	if err := s.establishSession(e, sub); err != nil {
		return err
	}

	e.NoContent()

	return nil
}

// establishSession generates a high-entropy session key, persists the
// session mapping for the subject, and sets the session cookie on the
// user-agent. It is shared by the password login and external login flows.
func (s *Server) establishSession(e *router.Exchange, sub Subject) error {
	key, err := s.generateSessionKey(e.Context())
	if err != nil {
		return s.internalError("failed to generate session key",
			err,
		)
	}

	if err := s.subjects.CreateSession(e.Context(), key, sub.ID()); err != nil {
		return s.internalError("failed to create subject session",
			err,
		)
	}

	e.SetCookie(s.newSessionCookie(key, 0))

	return nil
}

// Logout terminates the resource owner's session.
//
// It identifies the session via the session cookie, deletes the mapping from
// the [SubjectStore], and clears the cookie on the user-agent by setting a
// negative Max-Age value.
func (s *Server) Logout(e *router.Exchange) error {
	cookie, err := e.Cookie(s.sessionCookieName)
	if err == nil && cookie.Value != "" {
		if err := s.subjects.DeleteSession(
			e.Context(),
			cookie.Value,
		); err != nil {
			s.logger.ErrorContext(
				e.Context(),
				"Failed to delete subject session",
				slog.Any("error", err),
			)
		}
	}

	// Instruct the browser to wipe all local state (cookies, storage, cache).
	// Note: The double-quotes around the asterisk are required by the spec.
	e.SetHeader("Clear-Site-Data", `"*"`)

	e.SetCookie(s.newSessionCookie("", -1))

	e.NoContent()

	return nil
}

// ExternalLogin initiates a social authentication flow by redirecting the
// resource owner to the requested external identity provider.
func (s *Server) ExternalLogin(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := s.idps[name]
	if !ok {
		e.Status(http.StatusNotFound)
		return nil
	}

	state, err := s.generateState(e.Context())
	if err != nil {
		return s.internalError("failed to generate state", err)
	}

	e.SetCookie(s.newStateCookie(state, 300))

	authURL, err := idp.AuthURL(e.Context(), state)
	if err != nil {
		return s.internalError("failed to initiate external login",
			err,
		)
	}

	return e.Redirect(authURL, http.StatusFound)
}

// ExternalCallback handles the redirect from an external identity provider,
// verifies the state, exchanges credentials for an external identity, and
// establishes a local session.
//
// If a protocol or server error occurs during the exchange, the user-agent
// is redirected back to the configured login portal with the error details
// appended as query parameters.
func (s *Server) ExternalCallback(e *router.Exchange) error {
	err := s.externalCallback(e)
	if v, ok := errors.AsType[*router.Error](err); ok {
		u, err := url.Parse(s.loginTerminalURI)
		if err != nil {
			return s.internalError("failed to parse login terminal URI",
				err,
			)
		}
		q := u.Query()
		q.Set("error_status", strconv.Itoa(v.Status))
		q.Set("error_reason", v.Reason)
		q.Set("error_description", v.Description)
		if v.ID != "" {
			q.Set("error_id", v.ID)
		}
		u.RawQuery = q.Encode()

		// The user-agent sits in a top-level navigation here, so the error
		// must be delivered as an actual redirect back to the login portal.
		return e.Redirect(u.String(), http.StatusFound)
	}

	return err
}

func (s *Server) externalCallback(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := s.idps[name]
	if !ok {
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      router.ReasonNotFound,
			Description: "unknown identity provider",
		}
	}

	cookie, err := e.Cookie(s.stateCookieName)
	if err != nil || cookie.Value == "" {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "missing or expired state cookie",
		}
	}

	// Clear the state cookie immediately to prevent replay attacks.
	e.SetCookie(s.newStateCookie("", -1))

	// FormValue transparently covers both query-mode (GET) and form_post
	// (POST) callback responses.
	state := e.R.FormValue("state")
	if state != cookie.Value {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "state mismatch",
		}
	}

	identity, err := idp.Exchange(e.Context(), e.R)
	if err != nil {
		id := router.ErrorID()

		s.logger.ErrorContext(
			e.Context(),
			"Failed to process external exchange",
			slog.String("idp", name),
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "failed to exchange external credentials",
			ID:          id,
		}
	}

	sub, err := s.subjects.GetSubjectByExternalID(
		e.Context(),
		name,
		identity,
	)
	if err != nil {
		return s.internalError("failed to lookup subject", err)
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "external identity is not linked to any local subject",
		}
	}

	if err := s.establishSession(e, sub); err != nil {
		return err
	}

	return e.Redirect(s.loginRedirectURI, http.StatusFound)
}
