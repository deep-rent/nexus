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

package mock

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"slices"
	"sync"

	"uuid"

	"github.com/deep-rent/nexus/dat/diff"
	"github.com/deep-rent/nexus/dat/diff/hlc"
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

	// Granted maps document owners to the teams granted access to their
	// personal documents. It emulates the driver-side share lookup; the
	// shares handler writes through to it, and tests may also populate it
	// directly.
	Granted map[uuid.UUID][]uuid.UUID

	// Locked records the deduplicated, sorted union of shared and
	// exclusive keys of every Lock call.
	Locked [][]uuid.UUID
	// Exclusive records the deduplicated, sorted exclusive keys of every
	// Lock call.
	Exclusive [][]uuid.UUID
	// Touched records every owner whose personal documents were
	// re-sequenced by a landing share grant.
	Touched []uuid.UUID

	// Error injection: when set, the corresponding method fails.
	ErrExec      error
	ErrLock      error
	ErrFloor     error
	ErrBarrier   error
	ErrWatermark error
	ErrClaim     error
	ErrGrants    error
	ErrTouch     error

	// OnLock, if set, is invoked at the end of every [Store.Lock] call. It
	// lets a test simulate a concurrent ownership change landing during the
	// engine's resolve/lock/verify window, exercising the drift-retry path.
	OnLock func()
}

// New initializes an empty in-memory store.
func New() *Store {
	return &Store{
		claimed: make(map[uuid.UUID]struct{}),
		Granted: make(map[uuid.UUID][]uuid.UUID),
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
func (s *Store) Lock(
	_ context.Context,
	_ *Tx,
	shared, exclusive []uuid.UUID,
) error {
	if s.ErrLock != nil {
		return s.ErrLock
	}
	compare := func(a, b uuid.UUID) int { return a.Compare(b) }
	all := slices.Concat(shared, exclusive)
	slices.SortFunc(all, compare)
	all = slices.Compact(all)
	write := slices.Clone(exclusive)
	slices.SortFunc(write, compare)
	write = slices.Compact(write)

	s.mu.Lock()
	s.Locked = append(s.Locked, all)
	s.Exclusive = append(s.Exclusive, write)
	hook := s.OnLock
	s.mu.Unlock()

	if hook != nil {
		hook()
	}
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
	_ uuid.UUID,
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

// Grants implements the [diff.Store] interface.
func (s *Store) Grants(
	_ context.Context,
	_ *Tx,
	owners []uuid.UUID,
) (map[uuid.UUID][]uuid.UUID, error) {
	if s.ErrGrants != nil {
		return nil, s.ErrGrants
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[uuid.UUID][]uuid.UUID, len(owners))
	for _, owner := range owners {
		if teams := s.Granted[owner]; len(teams) > 0 {
			out[owner] = slices.Clone(teams)
		}
	}
	return out, nil
}

// touch re-sequences all personal documents of the given owner across
// every registered handler. The shares handler invokes it when a grant
// lands.
func (s *Store) touch(ownerID uuid.UUID) error {
	if s.ErrTouch != nil {
		return s.ErrTouch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Touched = append(s.Touched, ownerID)

	for _, h := range s.handlers {
		for _, r := range h.rows {
			if r.meta.UserID == ownerID && r.meta.TeamID == uuid.Nil() {
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
func (s *Store) granted(owner uuid.UUID, teams []uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, team := range s.Granted[owner] {
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
	ErrRead   error

	// OnFetch, if set, is invoked at the start of every [Handler.Fetch]
	// call. It lets a test simulate a concurrent tombstone prune advancing
	// the retention floor mid-scan, exercising the post-feed resync recheck.
	OnFetch func()
}

// NewHandler initializes an in-memory handler and registers it with the
// store so grant-triggered re-sequencing can reach its rows.
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
			// immutable. Note: unlike the reference driver, this flat
			// handler models neither team-move departure tombstones nor
			// parent/child cascades (see driver/drivertest capabilities).
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
	if h.OnFetch != nil {
		h.OnFetch()
	}
	if h.ErrFetch != nil {
		return nil, h.ErrFetch
	}

	visible := func(meta diff.Meta) bool {
		if scope.Allows(meta.UserID, meta.TeamID) {
			return true
		}
		return meta.TeamID == uuid.Nil() &&
			h.store.granted(meta.UserID, scope.Teams)
	}

	var out []diff.Version
	for id, r := range h.rows {
		if r.seq > w.Since && r.seq < w.Until && visible(r.meta) {
			out = append(out, diff.Version{
				ID:   id,
				Seq:  r.seq,
				Time: r.hlc,
				Data: r.data,
			})
		}
	}
	for id, ts := range h.tombs {
		if ts.seq > w.Since && ts.seq < w.Until && visible(ts.meta) {
			out = append(out, diff.Version{
				ID:      id,
				Seq:     ts.seq,
				Time:    ts.hlc,
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

// Read implements the [diff.Reader] interface with the same visibility
// rules as [Handler.Fetch]. Absent, deleted, and out-of-scope documents
// uniformly report ok == false.
func (h *Handler) Read(
	_ context.Context,
	_ *Tx,
	scope diff.Scope,
	id uuid.UUID,
) (diff.Version, bool, error) {
	h.Calls = append(h.Calls, "read")
	if h.ErrRead != nil {
		return diff.Version{}, false, h.ErrRead
	}

	r, exists := h.rows[id]
	if !exists {
		return diff.Version{}, false, nil
	}
	visible := scope.Allows(r.meta.UserID, r.meta.TeamID) ||
		(r.meta.TeamID == uuid.Nil() &&
			h.store.granted(r.meta.UserID, scope.Teams))
	if !visible {
		return diff.Version{}, false, nil
	}
	return diff.Version{
		ID:   id,
		Seq:  r.seq,
		Time: r.hlc,
		Data: r.data,
	}, true, nil
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
	_ diff.Reader[*Tx]  = (*Handler)(nil)
)

// Shares is the in-memory handler for the reserved share model. It applies
// last-write-wins like [Handler], writes grants through to
// [Store.Granted], and re-sequences the owner's personal documents when a
// grant lands. Construct instances with [NewShares].
type Shares struct {
	*Handler
}

// NewShares initializes the shares handler backed by the given store.
func NewShares(s *Store) *Shares {
	return &Shares{Handler: NewHandler(s)}
}

// Upsert implements the [diff.Handler] interface.
func (h *Shares) Upsert(
	ctx context.Context,
	tx *Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	before := len(h.rows)
	changed := make(map[uuid.UUID]hlc.Time, len(ops))
	for _, op := range ops {
		if r, ok := h.rows[op.Meta.ID]; ok {
			changed[op.Meta.ID] = r.hlc
		}
	}
	if err := h.Handler.Upsert(ctx, tx, scope, ops); err != nil {
		return err
	}

	landed := len(h.rows) > before
	for id, prev := range changed {
		if r, ok := h.rows[id]; ok && r.hlc != prev {
			landed = true
		}
	}
	h.sync()

	// A landing grant re-feeds the owner's personal documents to the newly
	// granted team members.
	if landed {
		return h.store.touch(scope.UserID)
	}
	return nil
}

// Delete implements the [diff.Handler] interface.
func (h *Shares) Delete(
	ctx context.Context,
	tx *Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	if err := h.Handler.Delete(ctx, tx, scope, ops); err != nil {
		return err
	}
	h.sync()
	return nil
}

// sync rebuilds the store's grant lookup from the live share rows.
func (h *Shares) sync() {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	clear(h.store.Granted)
	for _, r := range h.rows {
		if r.meta.TeamID != uuid.Nil() {
			h.store.Granted[r.meta.UserID] = append(
				h.store.Granted[r.meta.UserID], r.meta.TeamID,
			)
		}
	}
}

var _ diff.Handler[*Tx] = (*Shares)(nil)
