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
func (p *Server) Login(e *router.Exchange) error {
	var cred LoginRequest
	if err := e.BindJSON(&cred); err != nil {
		return err
	}

	sub, err := p.subjects.Authenticate(
		e.Context(),
		cred.Username,
		cred.Password,
	)
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Subject authentication lookup failed",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to lookup subject",
			ID:          id,
		}
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      router.ReasonValidationFailed,
			Description: "invalid credentials",
		}
	}

	key, err := p.generateSessionKey(e.Context())
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate session key",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to generate session key",
			ID:          id,
		}
	}

	if err := p.subjects.CreateSession(e.Context(), key, sub.ID()); err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to create subject session",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to create subject session",
			ID:          id,
		}
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

// Logout terminates the resource owner's session.
//
// It identifies the session via the session cookie, deletes the mapping from
// the [SubjectStore], and clears the cookie on the user-agent by setting a
// negative Max-Age value.
func (p *Server) Logout(e *router.Exchange) error {
	cookie, err := e.Cookie(p.sessionCookieName)
	if err == nil && cookie.Value != "" {
		if err := p.subjects.DeleteSession(e.Context(), cookie.Value); err != nil {
			p.logger.ErrorContext(
				e.Context(),
				"Failed to delete subject session",
				slog.Any("error", err),
			)
		}
	}

	// Instruct the browser to wipe all local state (cookies, storage, cache).
	// Note: The double-quotes around the asterisk are required by the spec.
	e.SetHeader("Clear-Site-Data", `"*"`)

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

// ExternalLogin initiates a social authentication flow by redirecting the
// resource owner to the requested external identity provider.
func (p *Server) ExternalLogin(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := p.idps[name]
	if !ok {
		e.Status(http.StatusNotFound)
		return nil
	}

	state, err := p.generateState(e.Context())
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate state",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to generate state",
			ID:          id,
		}
	}

	e.SetCookie(&http.Cookie{
		Name:     p.stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	authURL, err := idp.AuthURL(e.Context(), state)
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate auth url",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to initiate external login",
			ID:          id,
		}
	}

	e.SetHeader("Location", authURL)
	e.Status(http.StatusFound)

	return nil
}

// ExternalCallback handles the redirect from an external identity provider,
// verifies the state, exchanges credentials for an external identity, and
// establishes a local session.
//
// If a protocol or server error occurs during the exchange, the user-agent
// is redirected back to the configured login portal with the error details
// appended as query parameters.
func (p *Server) ExternalCallback(e *router.Exchange) error {
	err := p.externalCallback(e)
	if v, ok := errors.AsType[*router.Error](err); ok {
		u, err := url.Parse(p.loginTerminalURI)
		if err != nil {
			id := router.ErrorID()

			p.logger.ErrorContext(
				e.Context(),
				"Failed to parse login terminal URI",
				slog.String("error_id", id),
				slog.Any("error", err),
			)

			return &router.Error{
				Status:      http.StatusInternalServerError,
				Reason:      router.ReasonServerError,
				Description: "failed to parse login terminal URI",
				ID:          id,
			}
		}
		q := u.Query()
		q.Set("error_status", strconv.Itoa(v.Status))
		q.Set("error_reason", v.Reason)
		q.Set("error_description", v.Description)
		if v.ID != "" {
			q.Set("error_id", v.ID)
		}
		u.RawQuery = q.Encode()

		e.SetHeader("Location", u.String())
		e.Status(v.Status)

		return nil
	}

	return err
}

func (p *Server) externalCallback(e *router.Exchange) error {
	name := e.R.PathValue("provider")
	idp, ok := p.idps[name]
	if !ok {
		return &router.Error{
			Status:      http.StatusNotFound,
			Reason:      router.ReasonValidationFailed,
			Description: "unknown identity provider",
		}
	}

	cookie, err := e.Cookie(p.stateCookieName)
	if err != nil || cookie.Value == "" {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "missing or expired state cookie",
		}
	}

	// Clear the state cookie immediately to prevent replay attacks.
	e.SetCookie(&http.Cookie{
		Name:     p.stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	queryState := e.Query().Get("state")
	if queryState != cookie.Value {
		return &router.Error{
			Status:      http.StatusBadRequest,
			Reason:      router.ReasonValidationFailed,
			Description: "state mismatch",
		}
	}

	identity, err := idp.Process(e.Context(), e.R)
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to process external exchange",
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

	sub, err := p.subjects.GetSubjectByExternalID(
		e.Context(),
		name,
		identity,
	)
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"External subject lookup failed",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to lookup subject",
			ID:          id,
		}
	}
	if sub == nil {
		return &router.Error{
			Status:      http.StatusUnauthorized,
			Reason:      auth.ReasonAuthenticationFailed,
			Description: "external identity is not linked to any local subject",
		}
	}

	key, err := p.generateSessionKey(e.Context())
	if err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to generate session key",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to generate session key",
			ID:          id,
		}
	}

	if err := p.subjects.CreateSession(e.Context(), key, sub.ID()); err != nil {
		id := router.ErrorID()

		p.logger.ErrorContext(
			e.Context(),
			"Failed to create subject session",
			slog.String("error_id", id),
			slog.Any("error", err),
		)

		return &router.Error{
			Status:      http.StatusInternalServerError,
			Reason:      router.ReasonServerError,
			Description: "failed to create subject session",
			ID:          id,
		}
	}

	e.SetCookie(&http.Cookie{
		Name:     p.sessionCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	e.SetHeader("Location", p.loginRedirectURI)
	e.Status(http.StatusFound)

	return nil
}
