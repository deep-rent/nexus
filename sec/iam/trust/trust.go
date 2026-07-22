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

// Package trust manages remember-me device trust: high-entropy tokens that
// mark a device as trusted by its owner, so later logins on it may skip
// authentication factors within the trust window.
//
// The [Manager] is a transport-agnostic engine in the style of
// [github.com/deep-rent/nexus/sec/iam/otp.Challenger]: it mints, checks, and
// revokes trust tokens over a [Store], hashing every token before it reaches
// the store so a leaked datastore yields no usable trust. How the raw token
// travels — typically an httpOnly cookie — is the caller's concern.
package trust

import (
	"context"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/nonce"
)

// DefaultLifetime is the trust window applied by [New] when [WithLifetime] is
// not given.
const DefaultLifetime = 30 * 24 * time.Hour

// Record is the persisted state of a device trust. The token is stored only
// as its digest, never in the clear.
type Record struct {
	// ID is the digest of the trust token and the storage key. The plaintext
	// token never reaches the store.
	ID string `json:"id"`
	// Owner is an opaque reference to whoever trusts the device (e.g. a
	// subject ID). Trust is honored only for the same owner.
	Owner string `json:"owner"`
	// ExpiresAt is when the trust lapses, as a Unix timestamp in seconds.
	ExpiresAt int64 `json:"expires_at"`
	// Label is an optional human-facing hint for a device list, such as a
	// summary of the user agent. It never carries a secret.
	Label string `json:"label,omitzero"`
}

// Device is the result of a trust [Manager.Check]: whether the presented
// token proves the device trusted, and under which stable identifier.
type Device struct {
	// Trusted reports whether the device presented a live trust token bound
	// to the owner.
	Trusted bool
	// ID identifies the trust record (the token digest). It is stable across
	// checks, so callers may use it to key per-device state.
	ID string
}

// Store persists trust records keyed by [Record.ID]. See [artifact.Store]
// for the storage contract.
type Store interface {
	artifact.Store[string, Record]

	// DeleteForOwner removes every trust record enrolled by the given owner.
	// It backs a "sign out everywhere" or a credential-change revocation, and
	// is a no-op when the owner trusts no devices.
	DeleteForOwner(ctx context.Context, owner string) error
}

// Manager runs the lifecycle of device trust tokens — minting, checking, and
// revoking them — over a [Store]. It is safe for concurrent use if its
// [Store] is.
type Manager struct {
	store    Store
	lifetime time.Duration
	hasher   *digest.Hasher
	handles  *nonce.Generator
	now      func() time.Time
}

// Option configures a [Manager].
type Option func(*Manager)

// WithLifetime sets the trust window of a freshly issued token. Nonpositive
// values are ignored. Defaults to [DefaultLifetime].
func WithLifetime(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.lifetime = d
		}
	}
}

// WithHasher sets the hasher that fingerprints trust tokens before they reach
// the store. A nil hasher is ignored. Defaults to [digest.DefaultHasher].
func WithHasher(h *digest.Hasher) Option {
	return func(m *Manager) {
		if h != nil {
			m.hasher = h
		}
	}
}

// WithGenerator overrides the source of trust tokens. A nil generator is
// ignored. Defaults to [nonce.DefaultGenerator] (256-bit tokens).
func WithGenerator(g *nonce.Generator) Option {
	return func(m *Manager) {
		if g != nil {
			m.handles = g
		}
	}
}

// WithClock overrides the time source, primarily for testing. A nil function
// is ignored. Defaults to [time.Now].
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}

// New creates a [Manager] backed by the given [Store]. It panics if store is
// nil, since that is a startup configuration error.
func New(store Store, opts ...Option) *Manager {
	if store == nil {
		panic("store is required")
	}
	m := &Manager{
		store:    store,
		lifetime: DefaultLifetime,
		hasher:   digest.DefaultHasher,
		handles:  nonce.DefaultGenerator,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Issue mints a trust token for the owner, persists its digest, and returns
// the raw token for the caller to set on the client. The label is an optional
// human-facing hint stored alongside the record.
func (m *Manager) Issue(
	ctx context.Context,
	owner, label string,
) (token string, err error) {
	token, err = m.handles.Draw(ctx)
	if err != nil {
		return "", err
	}
	if err := m.store.Create(ctx, Record{
		ID:        m.hasher.String(token),
		Owner:     owner,
		ExpiresAt: m.now().Add(m.lifetime).Unix(),
		Label:     label,
	}); err != nil {
		return "", err
	}
	return token, nil
}

// Check reports whether the raw token proves the requesting device is trusted
// for the given owner.
//
// The trust is bound to the owner: a token issued for one owner never trusts
// a device for another. An empty token, an unknown or expired record, or a
// record for a different owner all yield an untrusted [Device], so a wrong or
// stale token simply falls back to full authentication. The error is reserved
// for storage failures.
func (m *Manager) Check(
	ctx context.Context,
	token, owner string,
) (Device, error) {
	if token == "" {
		return Device{}, nil
	}
	r, found, err := m.store.Get(ctx, m.hasher.String(token))
	if err != nil {
		return Device{}, err
	}
	if !found ||
		r.Owner != owner ||
		(r.ExpiresAt != 0 && m.now().Unix() > r.ExpiresAt) {
		return Device{}, nil
	}
	return Device{Trusted: true, ID: r.ID}, nil
}

// Revoke deletes the trust record for the raw token, if any. It is a no-op
// for an empty or unknown token.
func (m *Manager) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := m.store.Delete(ctx, m.hasher.String(token))
	return err
}

// RevokeAll removes every device trust enrolled by the owner. Call it when
// the owner's credentials change — for example on a password reset — so that
// no previously trusted device can skip authentication factors.
func (m *Manager) RevokeAll(ctx context.Context, owner string) error {
	return m.store.DeleteForOwner(ctx, owner)
}
