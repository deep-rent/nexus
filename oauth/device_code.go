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
	"time"
)

// deviceCodeGrant implements the [Grant] interface for the Device
// Authorization flow (RFC 8628).
type deviceCodeGrant struct{}

// DeviceCodeGrant returns a new grant implementation for the Device
// Authorization flow.
//
// Pass the result to [NewProvider] using [WithGrant] to enable this grant.
// Bear in mind that it requires the [Config.VerificationURI] option to be
// specified.
func DeviceCodeGrant() Grant {
	return deviceCodeGrant{}
}

// Type implements [Grant].
func (g deviceCodeGrant) Type() GrantType {
	return GrantTypeDeviceCode
}

// Authorize implements [Grant].
func (g deviceCodeGrant) Authorize(
	ctx context.Context,
	pro *Proposal,
) (*Issuance, error) {
	code := pro.Get("device_code")
	if code == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidRequest,
			Description: "missing device code",
		}
	}

	c, err := pro.Sessions.GetDeviceCode(ctx, code)
	if err != nil {
		pro.Logger.ErrorContext(
			ctx,
			"Failed to retrieve device code",
			slog.Any("error", err),
		)
		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to retrieve device code",
		}
	}

	if c.DeviceCode == "" {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "invalid device code",
		}
	}

	if c.ClientID != pro.Client.ID() {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidGrant,
			Description: "client mismatch",
		}
	}

	if time.Now().After(c.ExpiresAt) {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeExpiredToken,
			Description: "device code has expired",
		}
	}

	switch c.Status {
	case "pending":
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeAuthorizationPending,
			Description: "authorization pending",
		}
	case "denied":
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeAccessDenied,
			Description: "resource owner denied the request",
		}
	case "authorized":
		// Proceed to token issuance below.
	default:
		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "invalid device code status",
		}
	}

	// Delete the code immediately upon successful authorization to prevent reuse.
	if err := pro.Sessions.DeleteDeviceCode(ctx, code); err != nil {
		pro.Logger.ErrorContext(
			ctx,
			"Failed to delete device code",
			slog.Any("error", err),
		)
		return nil, &Error{
			Status:      http.StatusInternalServerError,
			Code:        ErrorCodeServerError,
			Description: "failed to delete device code",
		}
	}

	return &Issuance{
		Subject:     c.SubjectID,
		Scope:       c.Scope,
		Refreshable: true,
	}, nil
}

var _ Grant = (*deviceCodeGrant)(nil)
