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
	"log/slog"
	"net/http"

	"github.com/deep-rent/nexus/internal/pkce"
)

// authCodeGrant implements the [Grant] interface for the Authorization Code
// flow.
type authCodeGrant struct{}

// AuthCodeGrant returns a new grant implementation for the Authorization Code
// flow, including Proof Key for Code Exchange (PKCE) validation.
//
// Pass the result to [Provider.Register] to enable this grant.
func AuthCodeGrant() Grant {
	return &authCodeGrant{}
}

// Type implements [Grant].
func (g *authCodeGrant) Type() GrantType {
	return GrantTypeAuthorizationCode
}

// Authorize implements [Grant].
func (g *authCodeGrant) Authorize(
	ctx context.Context,
	pro *Proposal,
) (*Issuance, error) {
	code := pro.Get("code")
	if code == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing code",
		}
	}

	codeVerifier := pro.Get("code_verifier")
	if codeVerifier == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing code verifier",
		}
	}

	// Retrieve the authorization code state from the session store.
	c, err := pro.Sessions.GetAuthCode(ctx, code)
	if err != nil {
		pro.Logger.ErrorContext(
			ctx,
			"Failed to retrieve authorization code",
			slog.Any("error", err),
		)

		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve authorization code",
		}
	}

	// Ensure the code exists and has not expired.
	if c.Code == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid or expired authorization code",
		}
	}

	// Delete the code immediately to prevent replay attacks.
	if err := pro.Sessions.DeleteAuthCode(ctx, code); err != nil {
		pro.Logger.ErrorContext(
			ctx,
			"Failed to delete authorization code",
			slog.Any("error", err),
		)

		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to delete authorization code",
		}
	}

	// Validate that the client making the request is the one who requested it.
	if c.ClientID != pro.Client.ID() {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "client mismatch",
		}
	}

	// Validate the redirect URI if one was provided in the initial
	// authorization request.
	redirectURI := pro.Get("redirect_uri")
	if c.RedirectURI != "" {
		if redirectURI == "" {
			return nil, &Error{
				Status:      http.StatusBadRequest,
				Code:        ErrorCodeInvalidRequest,
				Description: "missing redirect URI",
			}
		}
		if c.RedirectURI != redirectURI {
			return nil, &Error{
				Status:      http.StatusBadRequest,
				Code:        ErrorCodeInvalidGrant,
				Description: "redirect URI mismatch",
			}
		}
	}

	// Perform PKCE verification to protect against interception.
	if !pkce.Verify(
		codeVerifier,
		c.CodeChallenge,
		c.CodeChallengeMethod,
	) {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "PKCE verification failed",
		}
	}

	return &Issuance{
		Subject:     c.SubjectID,
		Scope:       c.Scope,
		Refreshable: true,
	}, nil
}

var _ Grant = (*authCodeGrant)(nil)
