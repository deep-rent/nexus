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

	"uuid"
)

// TrustedDevice records that a subject has trusted a device, so a remembered
// login may skip authentication factors on it within the trust window.
//
// Like every bearer artifact, the token is stored only as its digest: a leaked
// datastore yields no usable trust tokens.
type TrustedDevice struct {
	// Token is the digest of the device trust token and the storage key. The
	// plaintext value never reaches the store.
	Token Digest `json:"token"`
	// SubjectID is the resource owner the device is trusted for. The trust is
	// honored only when the same subject authenticates again.
	SubjectID uuid.UUID `json:"subject_id"`
	// ExpiresAt is when the trust lapses, as a Unix timestamp in seconds.
	ExpiresAt int64 `json:"expires_at"`
	// Label is an optional human-facing hint for a device list, such as a
	// summary of the user agent. It never carries a secret.
	Label string `json:"label,omitzero"`
}

// issueTrustedDevice mints a device trust token for the subject, persists its
// digest, and returns the raw token for the caller to set on the client.
func (s *Server) issueTrustedDevice(
	ctx context.Context,
	subjectID uuid.UUID,
	label string,
) (string, error) {
	token, err := s.nonce.Draw(ctx)
	if err != nil {
		return "", err
	}
	if err := s.sessions.CreateTrustedDevice(ctx, TrustedDevice{
		Token:     NewDigest(token),
		SubjectID: subjectID,
		ExpiresAt: s.now().Add(s.trustedDeviceLifetime).Unix(),
		Label:     label,
	}); err != nil {
		return "", err
	}
	return token, nil
}

// deviceTrust reports whether the raw token proves the requesting device is
// trusted for the given subject.
//
// The trust is bound to the subject: a token issued for one resource owner
// never trusts a device for another. An empty token, an unknown or expired
// record, or a record for a different subject all yield an untrusted [Device],
// so a wrong or stale token simply falls back to full authentication.
func (s *Server) deviceTrust(
	ctx context.Context,
	token string,
	subjectID uuid.UUID,
) (Device, error) {
	if token == "" {
		return Device{}, nil
	}
	td, err := s.sessions.GetTrustedDevice(ctx, NewDigest(token))
	if err != nil {
		return Device{}, err
	}
	if td.Token == "" ||
		td.SubjectID != subjectID ||
		(td.ExpiresAt != 0 && s.now().Unix() > td.ExpiresAt) {
		return Device{}, nil
	}
	return Device{Trusted: true, ID: string(td.Token)}, nil
}

// revokeTrustedDevice deletes the trust record for the raw token, if any. It is
// a no-op for an empty or unknown token.
func (s *Server) revokeTrustedDevice(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.sessions.DeleteTrustedDevice(ctx, NewDigest(token))
	return err
}

// RevokeTrustedDevices removes every remember-me device trust enrolled by the
// subject. Call it when the subject's credentials change — for example on a
// password reset — so that no previously trusted device can skip authentication
// factors.
func (s *Server) RevokeTrustedDevices(
	ctx context.Context,
	subjectID uuid.UUID,
) error {
	return s.sessions.DeleteTrustedDevicesForSubject(ctx, subjectID)
}
