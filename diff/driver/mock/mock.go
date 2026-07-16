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

// Package mock provides an in-memory implementation of the diff storage
// contracts for unit testing. It faithfully reproduces the sequence,
// barrier, and claim semantics of a real driver without requiring a
// database. Handlers are not safe for concurrent use; drive them from a
// single goroutine per test.
package mock

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"slices"
	"sync"
	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/internal/hlc"
)

// Tx is the no-op transaction handle of the mock driver. All state lives in
// the [Store] and its handlers, guarded by a shared mutex.
type Tx struct{}

// Store is an in-memory implementation of [diff.Store]. The zero value is
// not usable; construct instances with [New]. Exported fields allow error
// injection and introspection in tests.
type Store struct {
	mu       sync.Mutex
	seq      int64
	floor    int64
	claimed  map[uuid.UUID]struct{}
	handlers []*Handler

	// Grants maps document owners to the teams granted access to their
	// personal documents. It emulates the driver-side share lookup and may
	// be populated directly by tests.
	Grants map[string][]string

	// Locked records the deduplicated, sorted lock set of every Lock call.
	Locked [][]string
	// Touched records every owner passed to Touch.
	Touched []string

	// Error injection: when set, the corresponding method fails.
	ErrExec      error
	ErrLock      error
	ErrFloor     error
	ErrBarrier   error
	ErrWatermark error
	ErrClaim     error
	ErrTouch     error
}

// New initializes an empty in-memory store.
func New() *Store {
	return &Store{
		claimed: make(map[uuid.UUID]struct{}),
		Grants:  make(map[string][]string),
	}
}

// SetFloor sets the retention floor returned by [Store.Floor].
func (s *Store) SetFloor(floor int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.floor = floor
}

// Exec implements the [diff.Store] interface.
func (s *Store) Exec(
	ctx context.Context,
	fn func(ctx context.Context, tx *Tx) error,
) error {
	if s.ErrExec != nil {
		return s.ErrExec
	}
	return fn(ctx, &Tx{})
}

// Lock implements the [diff.Store] interface.
func (s *Store) Lock(_ context.Context, _ *Tx, keys []string) error {
	if s.ErrLock != nil {
		return s.ErrLock
	}
	set := slices.Clone(keys)
	slices.Sort(set)
	set = slices.Compact(set)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.Locked = append(s.Locked, set)
	return nil
}

// Floor implements the [diff.Store] interface.
func (s *Store) Floor(_ context.Context, _ *Tx) (int64, error) {
	if s.ErrFloor != nil {
		return 0, s.ErrFloor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floor, nil
}

// Barrier implements the [diff.Store] interface.
func (s *Store) Barrier(_ context.Context, _ *Tx) (int64, error) {
	if s.ErrBarrier != nil {
		return 0, s.ErrBarrier
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq, nil
}

// Watermark implements the [diff.Store] interface.
func (s *Store) Watermark(_ context.Context, _ *Tx) (int64, error) {
	if s.ErrWatermark != nil {
		return 0, s.ErrWatermark
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq, nil
}

// Claim implements the [diff.Store] interface.
func (s *Store) Claim(
	_ context.Context,
	_ *Tx,
	_ string,
	ids []uuid.UUID,
) ([]uuid.UUID, error) {
	if s.ErrClaim != nil {
		return nil, s.ErrClaim
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var fresh []uuid.UUID
	for _, id := range ids {
		if _, seen := s.claimed[id]; !seen {
			s.claimed[id] = struct{}{}
			fresh = append(fresh, id)
		}
	}
	return fresh, nil
}

// Touch implements the [diff.Store] interface. It re-sequences all personal
// documents of the given owner across every registered handler.
func (s *Store) Touch(_ context.Context, _ *Tx, ownerID string) error {
	if s.ErrTouch != nil {
		return s.ErrTouch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Touched = append(s.Touched, ownerID)

	for _, h := range s.handlers {
		for _, r := range h.rows {
			if r.meta.UserID == ownerID && r.meta.TeamID == nil {
				s.seq++
				r.seq = s.seq
			}
		}
	}
	return nil
}

// next returns a fresh sequence value.
func (s *Store) next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq
}

// grants reports whether a personal document of the given owner is visible
// to any of the given teams.
func (s *Store) granted(owner string, teams []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, team := range s.Grants[owner] {
		if slices.Contains(teams, team) {
			return true
		}
	}
	return false
}

// row is one live document version.
type row struct {
	meta diff.Meta
	hlc  hlc.Time
	seq  int64
	data jsontext.Value
}

// Handler is an in-memory implementation of [diff.Handler] with row-level
// last-write-wins, tombstones, and scope guards. Construct instances with
// [NewHandler].
type Handler struct {
	store *Store
	rows  map[uuid.UUID]*row
	tombs map[uuid.UUID]*row // data is nil; hlc records the delete time

	// Calls records the order of Upsert/Delete/Fetch invocations as
	// "upsert"/"delete"/"fetch" strings for order assertions.
	Calls []string

	// Error injection: when set, the corresponding method fails.
	ErrUpsert error
	ErrDelete error
	ErrFetch  error
}

// NewHandler initializes an in-memory handler and registers it with the
// store so [Store.Touch] can reach its rows.
func NewHandler(s *Store) *Handler {
	if s == nil {
		panic("store is required")
	}
	h := &Handler{
		store: s,
		rows:  make(map[uuid.UUID]*row),
		tombs: make(map[uuid.UUID]*row),
	}
	s.mu.Lock()
	s.handlers = append(s.handlers, h)
	s.mu.Unlock()
	return h
}

// Upsert implements the [diff.Handler] interface.
func (h *Handler) Upsert(
	_ context.Context,
	_ *Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	h.Calls = append(h.Calls, "upsert")
	if h.ErrUpsert != nil {
		return h.ErrUpsert
	}

	for _, op := range ops {
		id := op.Meta.ID

		// A live tombstone beats stale upserts; newer upserts resurrect.
		if ts, dead := h.tombs[id]; dead {
			if op.Time <= ts.hlc {
				continue
			}
			delete(h.tombs, id)
		}

		if cur, exists := h.rows[id]; exists {
			// Row-level last-write-wins with hijack guard: the existing
			// row must be inside the caller's scope, and the owner is
			// immutable.
			if op.Time <= cur.hlc {
				continue
			}
			if !scope.Allows(cur.meta.UserID, cur.meta.TeamID) {
				continue
			}
			cur.meta.TeamID = op.Meta.TeamID
			cur.hlc = op.Time
			cur.seq = h.store.next()
			cur.data = op.Data
			continue
		}

		h.rows[id] = &row{
			meta: op.Meta,
			hlc:  op.Time,
			seq:  h.store.next(),
			data: op.Data,
		}
	}
	return nil
}

// Delete implements the [diff.Handler] interface.
func (h *Handler) Delete(
	_ context.Context,
	_ *Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	h.Calls = append(h.Calls, "delete")
	if h.ErrDelete != nil {
		return h.ErrDelete
	}

	for _, op := range ops {
		id := op.Meta.ID
		meta := op.Meta

		if cur, exists := h.rows[id]; exists {
			// Stale deletes and out-of-scope rows are silently skipped.
			if op.Time <= cur.hlc {
				continue
			}
			if !scope.Allows(cur.meta.UserID, cur.meta.TeamID) {
				continue
			}
			meta = cur.meta
			delete(h.rows, id)
		}

		if ts, dead := h.tombs[id]; dead && op.Time <= ts.hlc {
			continue
		}
		h.tombs[id] = &row{meta: meta, hlc: op.Time, seq: h.store.next()}
	}
	return nil
}

// Fetch implements the [diff.Handler] interface.
func (h *Handler) Fetch(
	_ context.Context,
	_ *Tx,
	scope diff.Scope,
	w diff.Window,
) ([]diff.Version, error) {
	h.Calls = append(h.Calls, "fetch")
	if h.ErrFetch != nil {
		return nil, h.ErrFetch
	}

	visible := func(meta diff.Meta) bool {
		if scope.Allows(meta.UserID, meta.TeamID) {
			return true
		}
		return meta.TeamID == nil &&
			h.store.granted(meta.UserID, scope.Teams)
	}

	var out []diff.Version
	for id, r := range h.rows {
		if r.seq > w.Since && r.seq < w.Until && visible(r.meta) {
			out = append(out, diff.Version{
				ID:   id,
				Seq:  r.seq,
				Data: r.data,
			})
		}
	}
	for id, ts := range h.tombs {
		if ts.seq > w.Since && ts.seq < w.Until && visible(ts.meta) {
			out = append(out, diff.Version{
				ID:      id,
				Seq:     ts.seq,
				Deleted: true,
			})
		}
	}

	slices.SortFunc(out, func(a, b diff.Version) int {
		return cmp.Compare(a.Seq, b.Seq)
	})
	if w.Limit > 0 && len(out) > w.Limit {
		out = out[:w.Limit]
	}
	return out, nil
}

// Resolve implements the [diff.Handler] interface.
func (h *Handler) Resolve(
	_ context.Context,
	_ *Tx,
	ids []uuid.UUID,
) (map[uuid.UUID]diff.Meta, error) {
	out := make(map[uuid.UUID]diff.Meta)
	for _, id := range ids {
		if r, exists := h.rows[id]; exists {
			out[id] = r.meta
		}
	}
	return out, nil
}

// Rows returns a snapshot of all live rows keyed by document ID, exposing
// sequence and payload for state assertions in tests.
func (h *Handler) Rows() map[uuid.UUID]diff.Version {
	out := make(map[uuid.UUID]diff.Version, len(h.rows))
	for id, r := range h.rows {
		out[id] = diff.Version{ID: id, Seq: r.seq, Data: r.data}
	}
	return out
}

// Tombstones returns a snapshot of all tombstoned document IDs.
func (h *Handler) Tombstones() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(h.tombs))
	for id := range h.tombs {
		out = append(out, id)
	}
	return out
}

var (
	_ diff.Store[*Tx]   = (*Store)(nil)
	_ diff.Handler[*Tx] = (*Handler)(nil)
)
