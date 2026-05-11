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

type refreshTokenGrant struct{}

// RefreshTokenGrant returns a new Grant implementation for the Refresh Token
// flow.
func RefreshTokenGrant() Grant {
	return &refreshTokenGrant{}
}

func (g *refreshTokenGrant) Type() GrantType {
	return GrantTypeRefreshToken
}

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

	if r.Token == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid or expired refresh token",
		}
	}

	if r.ClientID != pro.Client.ID() {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "client mismatch",
		}
	}

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
