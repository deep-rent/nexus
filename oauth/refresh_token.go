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
	"slices"
	"strings"
)

// refreshTokenGrant implements the [Grant] interface for token rotation.
type refreshTokenGrant struct{}

// RefreshTokenGrant returns a new grant implementation for the Refresh Token
// flow.
//
// Pass the result to [New] using [WithGrant] to enable this grant.
func RefreshTokenGrant() Grant {
	return refreshTokenGrant{}
}

// Type implements [Grant].
func (g refreshTokenGrant) Type() GrantType {
	return GrantTypeRefreshToken
}

// Authorize implements [Grant].
func (g refreshTokenGrant) Authorize(
	ctx context.Context,
	pro *Proposal,
) (*Issuance, error) {
	token := pro.Get("refresh_token")
	if token == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing refresh token",
		}
	}

	// The store only ever sees the digest of the token.
	digest := NewDigest(token)

	// Retrieve the refresh token details from the session store.
	r, err := pro.Sessions.GetRefreshToken(ctx, digest)
	if err != nil {
		return nil, pro.ServerError(
			ctx,
			"failed to retrieve refresh token",
			err,
		)
	}

	// Ensure the token exists.
	if r.Token == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	// Enforce expiry locally in addition to the store's TTL contract. An
	// expired token is removed as a best effort.
	if r.ExpiresAt != 0 && pro.Now().Unix() > r.ExpiresAt {
		if _, err := pro.Sessions.DeleteRefreshToken(ctx, digest); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to delete expired refresh token",
				slog.Any("error", err),
			)
		}
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	// Ensure the token belongs to the client attempting to use it.
	if r.ClientID != pro.Client.ID() {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
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
				return nil, &Error{
					Status:      http.StatusBadRequest,
					Code:        ErrorCodeInvalidScope,
					Description: "requested scope exceeds original grant",
				}
			}
		}
		scope = requested
	}

	// Revoke the old refresh token to ensure rotation security.
	// New tokens are issued by the [Server] later in the pipeline. If the
	// token was already gone, a concurrent rotation won the race and this
	// request must not issue tokens.
	deleted, err := pro.Sessions.DeleteRefreshToken(ctx, digest)
	if err != nil {
		return nil, pro.ServerError(
			ctx,
			"failed to revoke old refresh token",
			err,
		)
	}
	if !deleted {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	// RefreshScope carries the original grant scope so that a one-time
	// narrowing does not permanently downgrade the rotated refresh token.
	return &Issuance{
		Subject:      r.SubjectID,
		Scope:        scope,
		RefreshScope: r.Scope,
		Refreshable:  true,
	}, nil
}

var _ Grant = (*refreshTokenGrant)(nil)
