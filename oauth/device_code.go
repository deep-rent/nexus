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
	"fmt"
	"log/slog"
	"net/http"
)

// deviceCodeGrant implements the [Grant] interface for the Device
// Authorization flow (RFC 8628).
type deviceCodeGrant struct{}

// DeviceCodeGrant returns a new grant implementation for the Device
// Authorization flow.
//
// Pass the result to [New] using [WithGrant] to enable this grant.
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

	// The store only ever sees the digest of the code.
	digest := NewDigest(code)

	c, err := pro.Sessions.GetDeviceCode(ctx, digest)
	if err != nil {
		return nil, pro.ServerError(ctx, "failed to retrieve device code", err)
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

	now := pro.Now().Unix()

	// Expired codes are of no further use; remove them as a best effort.
	if c.ExpiresAt != 0 && now > c.ExpiresAt {
		if err := pro.Sessions.DeleteDeviceCode(ctx, digest); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to delete expired device code",
				slog.Any("error", err),
			)
		}
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeExpiredToken,
			Description: "device code has expired",
		}
	}

	// RFC 8628 Section 3.5: clients polling faster than the announced
	// interval must back off.
	if c.Interval > 0 && c.LastPolledAt != 0 &&
		now-c.LastPolledAt < c.Interval {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeSlowDown,
			Description: "polling too frequently",
		}
	}

	switch status := c.Status; status {
	case DeviceCodeStatusPending:
		c.LastPolledAt = now
		if err := pro.Sessions.UpdateDeviceCode(ctx, c); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to record device code poll",
				slog.Any("error", err),
			)
		}
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeAuthorizationPending,
			Description: "authorization pending",
		}
	case DeviceCodeStatusDenied:
		// The decision is final; remove the code as a best effort.
		if err := pro.Sessions.DeleteDeviceCode(ctx, digest); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to delete denied device code",
				slog.Any("error", err),
			)
		}
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeAccessDenied,
			Description: "resource owner denied the request",
		}
	case DeviceCodeStatusAuthorized:
		// Proceed to token issuance below.
	default:
		return nil, pro.ServerError(
			ctx,
			"illegal device code status",
			fmt.Errorf("unexpected status %q", status),
		)
	}

	// Delete the code immediately upon successful authorization to
	// prevent reuse.
	if err := pro.Sessions.DeleteDeviceCode(ctx, digest); err != nil {
		return nil, pro.ServerError(ctx, "failed to delete device code", err)
	}

	return &Issuance{
		Subject:     c.SubjectID,
		Scope:       c.Scope,
		Refreshable: true,
	}, nil
}

var _ Grant = (*deviceCodeGrant)(nil)
