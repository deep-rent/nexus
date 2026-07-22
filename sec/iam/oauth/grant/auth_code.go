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

package grant

import (
	"context"
	"net/http"

	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/oauth/pkce"
)

// authCode implements the [oauth.Grant] interface for the Authorization Code
// flow.
type authCode struct{}

// AuthCode returns a new grant implementation for the Authorization Code
// flow.
//
// Note: This implementation strictly mandates PKCE (RFC 7636) to mitigate
// authorization code injection and interception attacks.
//
// Register the result on the IAM server via
// [github.com/deep-rent/nexus/sec/iam.WithGrant] to enable this grant.
func AuthCode() oauth.Grant {
	return authCode{}
}

// Type implements [oauth.Grant].
func (g authCode) Type() oauth.GrantType {
	return oauth.GrantTypeAuthorizationCode
}

// Authorize implements [oauth.Grant].
func (g authCode) Authorize(
	ctx context.Context,
	pro *oauth.Proposal,
) (*oauth.Issuance, error) {
	code := pro.Get("code")
	if code == "" {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidRequest,
			Description: "missing code",
		}
	}

	codeVerifier := pro.Get("code_verifier")
	if codeVerifier == "" {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidRequest,
			Description: "missing code verifier",
		}
	}

	// The store only ever sees the digest of the code.
	digest := pro.Digest(code)

	// Retrieve the authorization code state from the session store.
	c, found, err := pro.Tokens.AuthCodes.Get(ctx, digest)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to retrieve authorization code",
			Cause:       err,
		}
	}

	// Ensure the code exists.
	if !found {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired authorization code",
		}
	}

	// Delete the code immediately to prevent replay attacks. Any failure
	// past this point intentionally burns the code. If the code was already
	// gone, a concurrent request won the race and this one must not issue
	// tokens.
	deleted, err := pro.Tokens.AuthCodes.Delete(ctx, digest)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to delete authorization code",
			Cause:       err,
		}
	}
	if !deleted {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired authorization code",
		}
	}

	// Enforce expiry locally in addition to the store's TTL contract.
	if c.ExpiresAt != 0 && pro.Now().Unix() > c.ExpiresAt {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired authorization code",
		}
	}

	// Validate that the client making the request is the one who requested it.
	if c.ClientID != pro.Client.ID() {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "client mismatch",
		}
	}

	// Validate the redirect URI if one was provided in the initial
	// authorization request.
	redirectURI := pro.Get("redirect_uri")
	if c.RedirectURI != "" {
		if redirectURI == "" {
			return nil, &oauth.Error{
				Status:      http.StatusBadRequest,
				Code:        oauth.ErrorCodeInvalidRequest,
				Description: "missing redirect uri",
			}
		}
		if c.RedirectURI != redirectURI {
			return nil, &oauth.Error{
				Status:      http.StatusBadRequest,
				Code:        oauth.ErrorCodeInvalidGrant,
				Description: "redirect uri mismatch",
			}
		}
	}

	// Perform PKCE verification to protect against interception.
	if !pkce.Verify(
		codeVerifier,
		c.CodeChallenge,
		c.CodeChallengeMethod,
	) {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "pkce verification failed",
		}
	}

	return &oauth.Issuance{
		Subject:     c.SubjectID,
		Scope:       c.Scope,
		Refreshable: true,
	}, nil
}

var _ oauth.Grant = (*authCode)(nil)
