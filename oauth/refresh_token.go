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
)

// refreshTokenGrant implements the [Grant] interface for token rotation.
type refreshTokenGrant struct{}

// RefreshTokenGrant returns a new grant implementation for the Refresh Token
// flow.
//
// Pass the result to [NewProvider] using [WithGrant] to enable this grant.
func RefreshTokenGrant() Grant {
	return &refreshTokenGrant{}
}

// Type implements [Grant].
func (g *refreshTokenGrant) Type() GrantType {
	return GrantTypeRefreshToken
}

// Authorize implements [Grant].
func (g *refreshTokenGrant) Authorize(
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

	// Retrieve the refresh token details from the session store.
	r, err := pro.Sessions.GetRefreshToken(ctx, token)
	if err != nil {
		pro.Logger.ErrorContext(
			ctx,
			"Failed to retrieve refresh token",
			slog.Any("error", err),
		)
		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve refresh token",
		}
	}

	// Ensure the token is valid and not yet expired.
	if r.Token == "" {
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

	// Revoke the old refresh token to ensure rotation security.
	// New tokens are issued by the [Provider] later in the pipeline.
	if err := pro.Sessions.DeleteRefreshToken(ctx, token); err != nil {
		pro.Logger.ErrorContext(
			ctx,
			"Failed to revoke old refresh token",
			slog.Any("error", err),
		)

		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to revoke old refresh token",
		}
	}

	return &Issuance{
		Subject:     r.SubjectID,
		Scope:       r.Scope,
		Refreshable: true,
	}, nil
}

var _ Grant = (*refreshTokenGrant)(nil)
