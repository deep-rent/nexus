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

package iam

import (
	"context"

	"uuid"

	"github.com/deep-rent/nexus/sec/iam/trust"
)

// issueTrustedDevice mints a device trust token for the subject, persists its
// digest, and returns the raw token for the caller to set on the client.
func (s *Server) issueTrustedDevice(
	ctx context.Context,
	subjectID uuid.UUID,
	label string,
) (string, error) {
	return s.trust.Issue(ctx, subjectID.String(), label)
}

// deviceTrust reports whether the raw token proves the requesting device is
// trusted for the given subject. A wrong or stale token — or a server without
// a trust store — simply yields an untrusted [trust.Device]; see
// [trust.Manager.Check].
func (s *Server) deviceTrust(
	ctx context.Context,
	token string,
	subjectID uuid.UUID,
) (trust.Device, error) {
	if s.trust == nil {
		return trust.Device{}, nil
	}
	return s.trust.Check(ctx, token, subjectID.String())
}

// RevokeTrustedDevices removes every remember-me device trust enrolled by the
// subject. Call it when the subject's credentials change — for example on a
// password reset — so that no previously trusted device can skip authentication
// factors. It is a no-op on a server without a trust store.
func (s *Server) RevokeTrustedDevices(
	ctx context.Context,
	subjectID uuid.UUID,
) error {
	if s.trust == nil {
		return nil
	}
	return s.trust.RevokeAll(ctx, subjectID.String())
}
