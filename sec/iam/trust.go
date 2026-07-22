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
	"fmt"

	"uuid"

	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/trust"
)

// TrustedDevice records that a subject has trusted a device, so a remembered
// login may skip authentication factors on it within the trust window. It is
// the stored shape of a [trust.Record].
//
// Like every bearer artifact, the token is stored only as its digest: a leaked
// datastore yields no usable trust tokens.
type TrustedDevice struct {
	// Token is the digest of the device trust token and the storage key. The
	// plaintext value never reaches the store.
	Token oauth.Digest `json:"token"`
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
	return s.trust.Issue(ctx, subjectID.String(), label)
}

// deviceTrust reports whether the raw token proves the requesting device is
// trusted for the given subject. A wrong or stale token simply yields an
// untrusted [trust.Device]; see [trust.Manager.Check].
func (s *Server) deviceTrust(
	ctx context.Context,
	token string,
	subjectID uuid.UUID,
) (trust.Device, error) {
	return s.trust.Check(ctx, token, subjectID.String())
}

// RevokeTrustedDevices removes every remember-me device trust enrolled by the
// subject. Call it when the subject's credentials change — for example on a
// password reset — so that no previously trusted device can skip authentication
// factors.
func (s *Server) RevokeTrustedDevices(
	ctx context.Context,
	subjectID uuid.UUID,
) error {
	return s.trust.RevokeAll(ctx, subjectID.String())
}

// trustStore adapts the server's [SessionStore] to the [trust.Store]
// interface, so existing SessionStore implementations back the device trust
// engine unchanged.
type trustStore struct {
	sessions SessionStore
}

var _ trust.Store = trustStore{}

// Create implements [trust.Store].
func (s trustStore) Create(ctx context.Context, r trust.Record) error {
	td, err := s.toTrustedDevice(r)
	if err != nil {
		return err
	}
	return s.sessions.CreateTrustedDevice(ctx, td)
}

// Get implements [trust.Store].
func (s trustStore) Get(
	ctx context.Context,
	id string,
) (trust.Record, bool, error) {
	td, err := s.sessions.GetTrustedDevice(ctx, oauth.Digest(id))
	if err != nil {
		return trust.Record{}, false, err
	}
	if td.Token == "" {
		return trust.Record{}, false, nil
	}
	return trust.Record{
		ID:        string(td.Token),
		Owner:     td.SubjectID.String(),
		ExpiresAt: td.ExpiresAt,
		Label:     td.Label,
	}, true, nil
}

// Delete implements [trust.Store].
func (s trustStore) Delete(ctx context.Context, id string) (bool, error) {
	return s.sessions.DeleteTrustedDevice(ctx, oauth.Digest(id))
}

// DeleteForOwner implements [trust.Store].
func (s trustStore) DeleteForOwner(ctx context.Context, owner string) error {
	sid, err := uuid.Parse(owner)
	if err != nil {
		return fmt.Errorf("invalid trust owner: %w", err)
	}
	return s.sessions.DeleteTrustedDevicesForSubject(ctx, sid)
}

// toTrustedDevice maps an engine record onto the stored shape, parsing the
// owner back into a subject ID.
func (s trustStore) toTrustedDevice(r trust.Record) (TrustedDevice, error) {
	sid, err := uuid.Parse(r.Owner)
	if err != nil {
		return TrustedDevice{}, fmt.Errorf("invalid trust owner: %w", err)
	}
	return TrustedDevice{
		Token:     oauth.Digest(r.ID),
		SubjectID: sid,
		ExpiresAt: r.ExpiresAt,
		Label:     r.Label,
	}, nil
}
