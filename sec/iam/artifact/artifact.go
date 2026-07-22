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

// Package artifact defines the storage contract shared by every ephemeral
// authorization artifact in the IAM machinery: authorization codes, refresh
// tokens, device codes, one-time password challenges, login flow
// transactions, device trust records, and WebAuthn ceremony sessions.
//
// All of them have the same shape — a record keyed by the digest of a bearer
// secret, bounded by a TTL, with create/read/update/delete lifecycle — so
// they all persist through one generic [Store]. A single storage backend
// (SQL, Redis, ...) can therefore be written once and instantiated per
// artifact type, and the in-memory [Map] serves every test.
//
// # The storage contract
//
// Keys are digests: the IAM engines hash every bearer secret before it
// crosses the Store boundary, so implementations never see plaintext values
// and a leaked datastore cannot be replayed against the server.
// Implementations must treat keys as opaque and persist them as-is.
//
// Absence is not an error: Get reports a missing (or expired-and-cleaned)
// record as found = false with a nil error. The error returns of all methods
// are reserved for storage failures.
//
// Deletion decides the winner: Delete must atomically remove the record and
// report whether this call was the one that removed it (e.g., SQL
// "DELETE ... RETURNING" or a Redis DEL count). The engines rely on that
// flag to enforce single use of codes, challenges, and handles under
// concurrent redemption — of two racing attempts, only the one whose Delete
// reports true may proceed.
//
// Records carry their expiry as a Unix timestamp; implementations may evict
// expired records eagerly (the engines double-check expiry on read), and
// production backends should, since nothing else reclaims the space.
package artifact

import (
	"context"
	"sync"
)

// Store persists ephemeral artifacts of type V keyed by K, the digest of a
// bearer secret. See the package documentation for the storage contract
// every implementation must honor.
//
// Implementations are expected to be safe for concurrent use and to honor
// the provided context.
type Store[K ~string, V any] interface {
	// Create persists a new record.
	Create(ctx context.Context, v V) error
	// Get returns the record with the given key. found is false when no such
	// record exists (including after expiry-driven cleanup); the returned
	// error is reserved for storage failures.
	Get(ctx context.Context, id K) (v V, found bool, err error)
	// Update persists changes to an existing record, keyed by its key.
	Update(ctx context.Context, v V) error
	// Delete removes the record with the given key, reporting whether it
	// existed and was removed by this call. The removal and the report must
	// be atomic; see the package documentation.
	Delete(ctx context.Context, id K) (deleted bool, err error)
}

// Map is a mutex-guarded in-memory [Store] keyed by a caller-provided key
// extractor.
//
// It is unbounded — nothing evicts expired records — and therefore meant for
// tests and local development, not production deployments. The exported
// [Map.Err] fault knob makes every method fail, so storage-error paths can
// be exercised without a bespoke fake.
type Map[K ~string, V any] struct {
	// Err, when non-nil, is returned by every method. Set it before use;
	// mutating it concurrently with store calls is not synchronized.
	Err error

	mu    sync.Mutex
	key   func(V) K
	items map[K]V
}

// NewMap creates an empty [Map] whose records are keyed by the given
// extractor. It panics if key is nil, since that is a static configuration
// error.
func NewMap[K ~string, V any](key func(V) K) *Map[K, V] {
	if key == nil {
		panic("key extractor is required")
	}
	return &Map[K, V]{key: key, items: make(map[K]V)}
}

// Create implements [Store].
func (m *Map[K, V]) Create(_ context.Context, v V) error {
	if m.Err != nil {
		return m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[m.key(v)] = v
	return nil
}

// Get implements [Store].
func (m *Map[K, V]) Get(_ context.Context, id K) (v V, found bool, err error) {
	if m.Err != nil {
		return v, false, m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, found = m.items[id]
	return v, found, nil
}

// Update implements [Store].
func (m *Map[K, V]) Update(_ context.Context, v V) error {
	if m.Err != nil {
		return m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[m.key(v)] = v
	return nil
}

// Delete implements [Store].
func (m *Map[K, V]) Delete(_ context.Context, id K) (bool, error) {
	if m.Err != nil {
		return false, m.Err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.items[id]
	delete(m.items, id)
	return ok, nil
}

// Len reports the number of stored records.
func (m *Map[K, V]) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// Range calls f for every stored record until f returns false. It iterates
// over a snapshot, so f may call back into the Map.
func (m *Map[K, V]) Range(f func(id K, v V) bool) {
	m.mu.Lock()
	snapshot := make(map[K]V, len(m.items))
	for k, v := range m.items {
		snapshot[k] = v
	}
	m.mu.Unlock()

	for k, v := range snapshot {
		if !f(k, v) {
			return
		}
	}
}
