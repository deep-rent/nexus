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

// Package session manages login sessions: high-entropy bearer keys that map
// a request back to an authenticated owner.
//
// The [Manager] is a transport-agnostic engine in the style of
// [github.com/deep-rent/nexus/sec/iam/otp.Challenger]: it mints, resolves,
// and destroys session keys over a [Store], hashing every key before it
// reaches the store so a leaked datastore yields no usable sessions. How the
// raw key travels — typically an httpOnly cookie — is the caller's concern,
// as is the lifetime policy: the caller passes each session's lifetime at
// establishment, so a "remember me" session may simply outlive a default
// one.
package session

import (
	"context"
	"time"

	"github.com/deep-rent/nexus/sec/digest"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/nonce"
)

// Record is the persisted state of a login session. The key is stored only
// as its digest, never in the clear.
type Record struct {
	// ID is the digest of the session key and the storage key. The plaintext
	// session key never reaches the store.
	ID string `json:"id"`
	// Owner is an opaque reference to the authenticated owner (e.g. a
	// subject ID). It is returned verbatim on successful resolution.
	Owner string `json:"owner"`
	// ExpiresAt is when the session lapses, as a Unix timestamp in seconds.
	// Zero marks a session without a server-side expiry.
	ExpiresAt int64 `json:"expires_at,omitzero"`
}

// Store persists sessions keyed by [Record.ID]. See [artifact.Store] for the
// storage contract.
type Store = artifact.Store[string, Record]

// Manager runs the lifecycle of login sessions — establishing, resolving,
// and destroying them — over a [Store]. It is safe for concurrent use if its
// [Store] is.
type Manager struct {
	store  Store
	hasher *digest.Hasher
	keys   *nonce.Generator
	now    func() time.Time
}


// New creates a [Manager] backed by the given [Store]. It panics if store is
// nil, since that is a startup configuration error.
func New(store Store, opts ...Option) *Manager {
	if store == nil {
		panic("store is required")
	}
	m := &Manager{
		store:  store,
		hasher: digest.DefaultHasher,
		keys:   nonce.DefaultGenerator,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Establish mints a session key for the owner, persists its digest, and
// returns the raw key for the caller to set on the client. The session
// expires after the given lifetime; a nonpositive lifetime stores a session
// without a server-side expiry.
func (m *Manager) Establish(
	ctx context.Context,
	owner string,
	lifetime time.Duration,
) (key string, err error) {
	key, err = m.keys.Draw(ctx)
	if err != nil {
		return "", err
	}

	r := Record{
		ID:    m.hasher.String(key),
		Owner: owner,
	}
	if lifetime > 0 {
		r.ExpiresAt = m.now().Add(lifetime).Unix()
	}
	if err := m.store.Create(ctx, r); err != nil {
		return "", err
	}
	return key, nil
}

// Resolve returns the owner behind the raw session key. ok is false when the
// key is empty, unknown, or expired, so a wrong or stale key simply reads as
// "not logged in". The error is reserved for storage failures.
func (m *Manager) Resolve(
	ctx context.Context,
	key string,
) (owner string, ok bool, err error) {
	if key == "" {
		return "", false, nil
	}
	r, found, err := m.store.Get(ctx, m.hasher.String(key))
	if err != nil {
		return "", false, err
	}
	if !found || (r.ExpiresAt != 0 && m.now().Unix() > r.ExpiresAt) {
		return "", false, nil
	}
	return r.Owner, true, nil
}

// Destroy removes the session behind the raw key, reporting whether one
// existed. It is a no-op, returning (false, nil), for an empty or unknown
// key.
func (m *Manager) Destroy(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, nil
	}
	return m.store.Delete(ctx, m.hasher.String(key))
}
