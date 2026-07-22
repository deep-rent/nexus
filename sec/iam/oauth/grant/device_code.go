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
	"fmt"
	"net/http"

	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sys/log"
)

// deviceCode implements the [oauth.Grant] interface for the Device
// Authorization flow (RFC 8628).
type deviceCode struct{}

// DeviceCode returns a new grant implementation for the Device
// Authorization flow.
//
// Register the result on the IAM server via
// [github.com/deep-rent/nexus/sec/iam.WithGrant] to enable this grant.
// Bear in mind that it requires the server's verification URI to be
// configured.
func DeviceCode() oauth.Grant {
	return deviceCode{}
}

// Type implements [oauth.Grant].
func (g deviceCode) Type() oauth.GrantType {
	return oauth.GrantTypeDeviceCode
}

// Authorize implements [oauth.Grant].
func (g deviceCode) Authorize(
	ctx context.Context,
	pro *oauth.Proposal,
) (*oauth.Issuance, error) {
	code := pro.Get("device_code")
	if code == "" {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidRequest,
			Description: "missing device code",
		}
	}

	// The store only ever sees the digest of the code.
	digest := pro.Digest(code)

	c, found, err := pro.Tokens.DeviceCodes.Get(ctx, digest)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to retrieve device code",
			Cause:       err,
		}
	}

	if !found {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid device code",
		}
	}

	if c.ClientID != pro.Client.ID() {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "client mismatch",
		}
	}

	now := pro.Now().Unix()

	// Expired codes are of no further use; remove them as a best effort.
	if c.ExpiresAt != 0 && now > c.ExpiresAt {
		if _, err := pro.Tokens.DeviceCodes.Delete(ctx, digest); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to delete expired device code",
				log.Err(err),
			)
		}
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeExpiredToken,
			Description: "device code has expired",
		}
	}

	// RFC 8628 Section 3.5: clients polling faster than the announced
	// interval must back off.
	if c.Interval > 0 && c.LastPolledAt != 0 &&
		now-c.LastPolledAt < c.Interval {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeSlowDown,
			Description: "polling too frequently",
		}
	}

	switch status := c.Status; status {
	case oauth.DeviceCodeStatusPending:
		// TouchDeviceCode only records the poll time, so a concurrent
		// approval via the verification endpoint can never be overwritten.
		if err := pro.Tokens.DeviceCodes.Touch(ctx, digest, now); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to record device code poll",
				log.Err(err),
			)
		}
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeAuthorizationPending,
			Description: "authorization pending",
		}
	case oauth.DeviceCodeStatusDenied:
		// The decision is final; remove the code as a best effort.
		if _, err := pro.Tokens.DeviceCodes.Delete(ctx, digest); err != nil {
			pro.Logger.ErrorContext(
				ctx,
				"Failed to delete denied device code",
				log.Err(err),
			)
		}
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeAccessDenied,
			Description: "resource owner denied the request",
		}
	case oauth.DeviceCodeStatusAuthorized:
		// Proceed to token issuance below.
	default:
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "illegal device code status",
			Cause:       fmt.Errorf("unexpected status %q", status),
		}
	}

	// Delete the code immediately upon successful authorization to prevent
	// reuse. If the code was already gone, a concurrent redemption won the
	// race and this request must not issue tokens.
	deleted, err := pro.Tokens.DeviceCodes.Delete(ctx, digest)
	if err != nil {
		return nil, &oauth.Error{
			Status:      http.StatusInternalServerError,
			Code:        oauth.ErrorCodeServerError,
			Description: "failed to delete device code",
			Cause:       err,
		}
	}
	if !deleted {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidGrant,
			Description: "invalid device code",
		}
	}

	return &oauth.Issuance{
		Subject:     c.SubjectID,
		Scope:       c.Scope,
		Refreshable: true,
	}, nil
}

var _ oauth.Grant = (*deviceCode)(nil)
