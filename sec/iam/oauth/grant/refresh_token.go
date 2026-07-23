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
	"slices"
	"strings"

	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sys/log"
)

// refreshToken implements the [oauth.Grant] interface for token rotation.
type refreshToken struct{}

// RefreshToken returns a new grant implementation for the Refresh Token
// flow.
//
// Register the result on the IAM server via
// [github.com/deep-rent/nexus/sec/iam.WithGrant] to enable this grant.
func RefreshToken() oauth.Grant {
	return refreshToken{}
}

// Type implements [oauth.Grant].
func (g refreshToken) Type() oauth.GrantType {
	return oauth.GrantTypeRefreshToken
}

// Authorize implements [oauth.Grant].
func (g refreshToken) Authorize(
	ctx context.Context,
	pro *oauth.Proposal,
) (*oauth.Issuance, error) {
	token := pro.Get("refresh_token")
	if token == "" {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidRequest,
			Description: "missing refresh token",
		}
	}

	// The store only ever sees the digest of the token.
	digest := pro.Digest(token)

	// Retrieve the refresh token details from the session store.
	r, found, err := pro.Tokens.RefreshTokens.Get(ctx, digest)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to retrieve refresh token",
			Cause:       err,
		}
	}

	// Ensure the token exists.
	if !found {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	// Enforce expiry locally in addition to the store's TTL contract. An
	// expired token is removed as a best effort.
	if r.ExpiresAt != 0 && pro.Now().Unix() > r.ExpiresAt {
		if _, err := pro.Tokens.RefreshTokens.Delete(ctx, digest); err != nil {
			pro.Logger.Error(
				ctx,
				"Failed to delete expired refresh token",
				log.Error(err),
			)
		}
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	// Ensure the token belongs to the client attempting to use it.
	if r.ClientID != pro.Client.ID() {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "client mismatch",
		}
	}

	// RFC 6749 Section 6: the client may request a narrower scope than
	// originally granted, but never a broader one.
	scope := r.Scope
	if requested := pro.Get("scope"); requested != "" {
		granted := strings.Fields(r.Scope)
		for sc := range strings.FieldsSeq(requested) {
			if !slices.Contains(granted, sc) {
				return nil, &oauth.Error{
					Status:      http.StatusBadRequest,
					Code:        oauth.ErrorCodeInvalidScope,
					Description: "requested scope exceeds original grant",
				}
			}
		}
		scope = requested
	}

	// Revoke the old refresh token to ensure rotation security.
	// New tokens are issued by the authorization server later in the
	// pipeline. If the token was already gone, a concurrent rotation won the
	// race and this request must not issue tokens.
	deleted, err := pro.Tokens.RefreshTokens.Delete(ctx, digest)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to revoke old refresh token",
			Cause:       err,
		}
	}
	if !deleted {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	// RefreshScope carries the original grant scope so that a one-time
	// narrowing does not permanently downgrade the rotated refresh token.
	return &oauth.Issuance{
		Subject:      r.SubjectID,
		Scope:        scope,
		RefreshScope: r.Scope,
		Refreshable:  true,
	}, nil
}

var _ oauth.Grant = (*refreshToken)(nil)
