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

package diff

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"uuid"

	"github.com/deep-rent/nexus/internal/hlc"
	"github.com/deep-rent/nexus/valid"
)

// Default engine limits.
const (
	// DefaultMaxChanges caps the number of changes accepted per request.
	DefaultMaxChanges = 500
	// DefaultMaxPatches caps the requestable patch feed page size.
	DefaultMaxPatches = 1000
	// DefaultLimit is the feed page size applied when the request omits one.
	DefaultLimit = 200
)

// config holds configuration options for the [Engine].
type config struct {
	logger     *slog.Logger
	clock      *hlc.Clock
	prefilter  Prefilter
	maxChanges int
	maxLimit   int
	defLimit   int
}

// Option is a functional option for configuring the [Engine].
type Option func(*config)

// WithLogger sets the logger used for structured sync diagnostics.
// If not provided, [slog.Default] is used. A nil logger is ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithClock injects the Hybrid Logical Clock instance, which is primarily
// useful for testing. A nil clock is ignored.
func WithClock(clock *hlc.Clock) Option {
	return func(c *config) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithPrefilter installs an optional fast-path duplicate filter consulted
// before the transaction. A nil prefilter is ignored.
func WithPrefilter(p Prefilter) Option {
	return func(c *config) {
		if p != nil {
			c.prefilter = p
		}
	}
}

// WithMaxChanges overrides [DefaultMaxChanges]. Non-positive values are
// ignored.
func WithMaxChanges(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxChanges = n
		}
	}
}

// WithMaxPatches overrides [DefaultMaxPatches]. Non-positive values are
// ignored.
func WithMaxPatches(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxLimit = n
		}
	}
}

// WithDefaultLimit overrides [DefaultLimit]. Non-positive values are
// ignored.
func WithDefaultLimit(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.defLimit = n
		}
	}
}

// Engine orchestrates the bidirectional sync pipeline: it ingests change
// sets and compiles patch feeds within a single transaction per request.
type Engine[Tx any] struct {
	store Store[Tx]
	reg   *Registry[Tx]
	cfg   config
}

// New creates a sync engine around the given store and type registry.
// It panics if store or registry is nil, no entity types are registered,
// or their declared relationships are cyclic or dangling (programmer
// error).
func New[Tx any](store Store[Tx], reg *Registry[Tx], opts ...Option) *Engine[Tx] {
	if store == nil {
		panic("store is required")
	}
	if reg == nil || len(reg.entries) == 0 {
		panic("registry with at least one entity type is required")
	}
	reg.order() // surface cycles and dangling references now

	cfg := config{
		logger:     slog.Default(),
		clock:      hlc.New(nil),
		maxChanges: DefaultMaxChanges,
		maxLimit:   DefaultMaxPatches,
		defLimit:   DefaultLimit,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Engine[Tx]{store: store, reg: reg, cfg: cfg}
}

// Now returns a fresh timestamp from the engine's clock. Backend-initiated
// writes to synced tables must stamp their rows with it.
func (e *Engine[Tx]) Now() hlc.Time {
	return e.cfg.clock.Now()
}

// change extends Op with ingestion bookkeeping.
type change struct {
	Op
	typ      string
	mutation uuid.UUID // client-assigned mutation id
	parent   uuid.UUID // referenced ownership parent (child types only)
	child    bool      // identity derives from the parent chain
	resolved bool      // identity in Meta is final
}

// errRetry signals that the lock set drifted between resolution and lock
// acquisition and the transaction must be retried.
var errRetry = errors.New("lock set drifted")

// Sync ingests the request's change set and compiles the patch feed the
// client missed, both within a single transaction. The returned error is
// one of the typed errors in this package (see endpoint.go for their HTTP
// mapping), or an operational error from the store.
func (e *Engine[Tx]) Sync(
	ctx context.Context,
	scope Scope,
	req *Request,
) (*Response, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = e.cfg.defLimit
	}
	limit = min(limit, e.cfg.maxLimit)

	if len(req.Changes) > e.cfg.maxChanges {
		return nil, ErrTooManyChanges
	}

	changes, err := e.screen(scope, req.Changes)
	if err != nil {
		return nil, err
	}

	ids := make([]uuid.UUID, 0, len(changes))
	for _, c := range changes {
		ids = append(ids, c.mutation)
	}
	if e.cfg.prefilter != nil && len(ids) > 0 {
		fresh, err := e.cfg.prefilter.Filter(ctx, ids)
		if err == nil {
			keep := make(map[uuid.UUID]struct{}, len(fresh))
			for _, id := range fresh {
				keep[id] = struct{}{}
			}
			changes = slices.DeleteFunc(changes, func(c *change) bool {
				_, ok := keep[c.mutation]
				return !ok
			})
			ids = fresh
		} else {
			e.cfg.logger.Warn("prefilter failed", slog.Any("error", err))
		}
	}

	winners := compact(changes)

	// The lock set may depend on document rows (child ownership chains), so
	// resolution and locking race against concurrent ownership changes:
	// resolve, lock, then re-verify; on drift, retry once with the union of
	// both lock sets before giving up.
	var resp *Response
	extra := make(map[uuid.UUID]struct{})
	for attempt := 0; ; attempt++ {
		err := e.store.Exec(ctx, func(ctx context.Context, tx Tx) error {
			keys, err := e.assemble(ctx, tx, scope, winners, extra)
			if err != nil {
				return err
			}
			if err := e.store.Lock(ctx, tx, keys); err != nil {
				return err
			}

			// Re-resolve under the locks; anything outside the held set
			// means a concurrent ownership change slipped in between.
			verify, err := e.assemble(ctx, tx, scope, winners, extra)
			if err != nil {
				return err
			}
			held := make(map[uuid.UUID]struct{}, len(keys))
			for _, k := range keys {
				held[k] = struct{}{}
			}
			for _, k := range verify {
				if _, ok := held[k]; !ok {
					extra[k] = struct{}{}
					return errRetry
				}
			}

			resp, err = e.sync(ctx, tx, scope, req, winners, ids, limit)
			return err
		})
		if errors.Is(err, errRetry) && attempt == 0 {
			continue
		}
		if errors.Is(err, errRetry) {
			return nil, ErrConflict
		}
		if err != nil {
			return nil, err
		}
		break
	}

	if e.cfg.prefilter != nil && len(ids) > 0 {
		if err := e.cfg.prefilter.Mark(ctx, ids); err != nil {
			e.cfg.logger.Warn("prefilter mark failed", slog.Any("error", err))
		}
	}

	e.cfg.logger.Info("sync completed",
		slog.String("user", scope.UserID.String()),
		slog.Int("received", len(req.Changes)),
		slog.Int("applied", len(winners)),
		slog.Int("patches", len(resp.Patches)),
		slog.Bool("more", resp.More),
	)
	return resp, nil
}

// screen validates and authorizes the raw changes without touching storage.
// It decodes each payload envelope, enforces scope on root identities,
// validates document payloads, and merges every timestamp into the engine
// clock. Violations are collected per class and returned as typed errors,
// most severe class first.
func (e *Engine[Tx]) screen(
	scope Scope,
	raw []Change,
) ([]*change, error) {
	var (
		unknownIDs   []uuid.UUID
		unknownTypes []string
		denied       []uuid.UUID
		drifted      []uuid.UUID
		invalid      = make(map[uuid.UUID]valid.Error)
	)

	changes := make([]*change, 0, len(raw))
	for i := range raw {
		in := &raw[i]
		entry, known := e.reg.lookup(in.Type)
		if !known {
			unknownIDs = append(unknownIDs, in.ID)
			if !slices.Contains(unknownTypes, in.Type) {
				unknownTypes = append(unknownTypes, in.Type)
			}
			continue
		}

		c := &change{
			Action:   in.Action,
			Time:     hlc.Time(in.Time),
			typ:      in.Type,
			mutation: in.ID,
		}
		if in.Action == ActionUpsert {
			c.Data = in.Data
		}

		if entry.root {
			var meta Meta
			if err := json.Unmarshal(in.Data, &meta); err != nil ||
				meta.ID == uuid.Nil() {
				invalid[in.ID] = valid.Error{
					"data": {"must carry a valid document envelope"},
				}
				continue
			}
			c.Meta = meta
			c.resolved = true

			// Payload identity is never trusted: it must lie inside the
			// caller's scope, and shares may only be issued by their owner.
			if !scope.Allows(meta.UserID, meta.TeamID) ||
				(in.Type == TypeShare && meta.UserID != scope.UserID) {
				denied = append(denied, in.ID)
				continue
			}
		} else {
			id, parent, err := envelope(in.Data, entry.ownerVia)
			if err != nil {
				invalid[in.ID] = valid.Error{
					"data": {"must carry a valid document envelope"},
				}
				continue
			}
			c.Meta.ID = id
			c.parent = parent
			c.child = true
			if in.Action == ActionUpsert && parent == uuid.Nil() {
				invalid[in.ID] = valid.Error{
					"data": {fmt.Sprintf(
						"must reference a parent document via %q",
						entry.ownerVia,
					)},
				}
				continue
			}
		}

		if in.Action == ActionUpsert {
			if verr := entry.check(in.Data); verr != nil {
				invalid[in.ID] = verr
				continue
			}
		}

		if _, err := e.cfg.clock.Update(hlc.Time(in.Time)); err != nil {
			if errors.Is(err, hlc.ErrClockDriftTooLarge) {
				drifted = append(drifted, in.ID)
				continue
			}
			return nil, err
		}

		changes = append(changes, c)
	}

	switch {
	case len(unknownIDs) > 0:
		return nil, &TypeError{IDs: unknownIDs, Types: unknownTypes}
	case len(denied) > 0:
		return nil, &AuthzError{IDs: denied}
	case len(invalid) > 0:
		return nil, &PayloadError{Errors: invalid}
	case len(drifted) > 0:
		return nil, &DriftError{IDs: drifted}
	}
	return changes, nil
}

// envelope extracts the document ID and the optional ownership parent
// reference from a child payload.
func envelope(data jsontext.Value, via string) (uuid.UUID, uuid.UUID, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(data, &fields); err != nil {
		return uuid.Nil(), uuid.Nil(), err
	}

	var id, parent uuid.UUID
	if raw, ok := fields["id"]; ok {
		if err := json.Unmarshal(raw, &id); err != nil {
			return uuid.Nil(), uuid.Nil(), err
		}
	}
	if id == uuid.Nil() {
		return uuid.Nil(), uuid.Nil(), errors.New("missing document id")
	}
	if raw, ok := fields[via]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &parent); err != nil {
			return uuid.Nil(), uuid.Nil(), err
		}
	}
	return id, parent, nil
}

// compact reduces the change set to one winning operation per document:
// the one carrying the highest (time, mutation id) pair. Losing mutations
// are still claimed for idempotency, but row-level last-write-wins makes
// their intermediate states unobservable, so they are never applied.
func compact(changes []*change) []*change {
	type key struct {
		typ string
		id  uuid.UUID
	}
	best := make(map[key]*change, len(changes))
	for _, c := range changes {
		k := key{typ: c.typ, id: c.Meta.ID}
		cur, exists := best[k]
		if !exists || c.Time > cur.Time ||
			(c.Time == cur.Time && c.mutation.Compare(cur.mutation) > 0) {
			best[k] = c
		}
	}

	winners := make([]*change, 0, len(best))
	for _, c := range changes { // preserve request order for determinism
		if best[key{typ: c.typ, id: c.Meta.ID}] == c {
			winners = append(winners, c)
		}
	}
	return winners
}

// assemble resolves child ownership chains and returns the full lock set:
// the caller's scope, every resolved root identity, and any extra keys
// carried over from a drifted previous attempt.
func (e *Engine[Tx]) assemble(
	ctx context.Context,
	tx Tx,
	scope Scope,
	winners []*change,
	extra map[uuid.UUID]struct{},
) ([]uuid.UUID, error) {
	if err := e.resolve(ctx, tx, winners); err != nil {
		return nil, err
	}

	set := make(map[uuid.UUID]struct{})
	set[scope.UserID] = struct{}{}
	for _, team := range scope.Teams {
		set[team] = struct{}{}
	}
	for _, c := range winners {
		if !c.resolved {
			continue // unresolvable delete, dropped later
		}
		set[c.Meta.UserID] = struct{}{}
		if c.Meta.TeamID != nil {
			set[*c.Meta.TeamID] = struct{}{}
		}
	}
	for k := range extra {
		set[k] = struct{}{}
	}

	keys := make([]uuid.UUID, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b uuid.UUID) int { return a.Compare(b) })
	return keys, nil
}

// resolve walks child ownership chains until every change carries its root
// identity: in-batch parents are chased transitively, everything else is
// looked up through the parent type's handler.
func (e *Engine[Tx]) resolve(
	ctx context.Context,
	tx Tx,
	winners []*change,
) error {
	// Child identities derive from mutable rows and may drift between
	// attempts, so they are re-derived on every call; root identities come
	// from the (immutable) payload and stay final.
	for _, c := range winners {
		if c.child {
			c.resolved = false
			c.Meta.UserID = uuid.Nil()
			c.Meta.TeamID = nil
		}
	}

	// Index in-batch upserts so children can inherit identity from parents
	// created in the same request.
	batch := make(map[string]map[uuid.UUID]*change)
	for _, c := range winners {
		if c.Action != ActionUpsert {
			continue
		}
		if batch[c.typ] == nil {
			batch[c.typ] = make(map[uuid.UUID]*change)
		}
		batch[c.typ][c.Meta.ID] = c
	}

	// Chains are acyclic and shallow (validated at registration), so a
	// bounded number of passes settles every change: each pass resolves
	// children whose parent identity is already known and batch-fetches the
	// rest from storage, level by level.
	for range len(e.reg.entries) + 1 {
		pending := make(map[string][]uuid.UUID) // parent type -> parent ids
		for _, c := range winners {
			if c.resolved {
				continue
			}
			entry, _ := e.reg.lookup(c.typ)

			if c.Action == ActionDelete && c.parent == uuid.Nil() {
				// Child deletes resolve through the stored row itself.
				pending[c.typ] = append(pending[c.typ], c.Meta.ID)
				continue
			}

			if p, ok := batch[entry.owner][c.parent]; ok {
				if p.resolved {
					c.Meta.UserID = p.Meta.UserID
					c.Meta.TeamID = p.Meta.TeamID
					c.resolved = true
				}
				continue // parent resolves in a later pass
			}
			pending[entry.owner] = append(pending[entry.owner], c.parent)
		}

		if len(pending) == 0 {
			break
		}

		found := make(map[string]map[uuid.UUID]Meta, len(pending))
		for typ, ids := range pending {
			entry, ok := e.reg.lookup(typ)
			if !ok {
				continue
			}
			metas, err := entry.handler.Resolve(ctx, tx, ids)
			if err != nil {
				return err
			}
			found[typ] = metas
		}

		for _, c := range winners {
			if c.resolved {
				continue
			}
			entry, _ := e.reg.lookup(c.typ)

			if c.Action == ActionDelete && c.parent == uuid.Nil() {
				if meta, ok := found[c.typ][c.Meta.ID]; ok {
					c.Meta.UserID = meta.UserID
					c.Meta.TeamID = meta.TeamID
					c.resolved = true
				}
				continue
			}
			if meta, ok := found[entry.owner][c.parent]; ok {
				c.Meta.UserID = meta.UserID
				c.Meta.TeamID = meta.TeamID
				c.resolved = true
			}
		}
	}

	// Upserts must resolve; deletes of never-seen children are dropped
	// silently later. An unresolvable upsert means the referenced parent
	// document does not exist.
	invalid := make(map[uuid.UUID]valid.Error)
	for _, c := range winners {
		if !c.resolved && c.Action == ActionUpsert {
			invalid[c.mutation] = valid.Error{
				"data": {"references a missing parent document"},
			}
		}
	}
	if len(invalid) > 0 {
		return &PayloadError{Errors: invalid}
	}
	return nil
}

// sync runs the transactional core: claim, apply, and feed.
func (e *Engine[Tx]) sync(
	ctx context.Context,
	tx Tx,
	scope Scope,
	req *Request,
	winners []*change,
	ids []uuid.UUID,
	limit int,
) (*Response, error) {
	floor, err := e.store.Floor(ctx, tx)
	if err != nil {
		return nil, err
	}
	if req.Since > 0 && int64(req.Since) < floor {
		return nil, &ResyncError{Floor: Cursor(floor)}
	}

	barrier, err := e.store.Barrier(ctx, tx)
	if err != nil {
		return nil, err
	}

	// Authorize resolved child identities: the root a child hangs off must
	// itself be accessible to the caller.
	var denied []uuid.UUID
	for _, c := range winners {
		if c.resolved && !scope.Allows(c.Meta.UserID, c.Meta.TeamID) {
			denied = append(denied, c.mutation)
		}
	}
	if len(denied) > 0 {
		return nil, &AuthzError{IDs: denied}
	}

	// Claim every mutation id; only winners whose own claim is fresh are
	// applied. Replayed requests thereby degrade to pure feed queries.
	claimed, err := e.store.Claim(ctx, tx, scope.UserID, ids)
	if err != nil {
		return nil, err
	}
	fresh := make(map[uuid.UUID]struct{}, len(claimed))
	for _, id := range claimed {
		fresh[id] = struct{}{}
	}

	upserts := make(map[string][]Op)
	deletes := make(map[string][]Op)
	shared := false
	for _, c := range winners {
		if _, ok := fresh[c.mutation]; !ok {
			continue
		}
		if !c.resolved {
			continue // delete of a never-seen child document
		}
		switch c.Action {
		case ActionUpsert:
			upserts[c.typ] = append(upserts[c.typ], c.Op)
			if c.typ == TypeShare {
				shared = true
			}
		case ActionDelete:
			deletes[c.typ] = append(deletes[c.typ], c.Op)
		}
	}

	order := e.reg.order()

	// Parents before children for upserts, children before parents for
	// deletes: mirrors client-side foreign key constraints.
	for _, typ := range order {
		if ops := upserts[typ]; len(ops) > 0 {
			entry, _ := e.reg.lookup(typ)
			if err := entry.handler.Upsert(ctx, tx, scope, ops); err != nil {
				return nil, err
			}
		}
	}
	for _, typ := range slices.Backward(order) {
		if ops := deletes[typ]; len(ops) > 0 {
			entry, _ := e.reg.lookup(typ)
			if err := entry.handler.Delete(ctx, tx, scope, ops); err != nil {
				return nil, err
			}
		}
	}

	// A fresh grant re-feeds the owner's personal documents to the newly
	// granted team members.
	if shared {
		if err := e.store.Touch(ctx, tx, scope.UserID); err != nil {
			return nil, err
		}
	}

	return e.feed(ctx, tx, scope, req.Since, barrier, limit)
}

// version tags a fetched row with its entity type during feed assembly.
type version struct {
	Version
	typ string
}

// feed compiles the patch feed for the window (since, barrier).
func (e *Engine[Tx]) feed(
	ctx context.Context,
	tx Tx,
	scope Scope,
	since Cursor,
	barrier int64,
	limit int,
) (*Response, error) {
	order := e.reg.order()

	var merged []version
	for _, typ := range order {
		entry, _ := e.reg.lookup(typ)
		rows, err := entry.handler.Fetch(ctx, tx, scope, Window{
			Since: int64(since),
			Until: barrier,
			Limit: limit + 1,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			merged = append(merged, version{Version: row, typ: typ})
		}
	}

	slices.SortFunc(merged, func(a, b version) int {
		return cmp.Compare(a.Seq, b.Seq)
	})

	more := len(merged) > limit
	if more {
		merged = merged[:limit]
	}

	var next Cursor
	if more {
		next = Cursor(merged[len(merged)-1].Seq)
	} else {
		mark, err := e.store.Watermark(ctx, tx)
		if err != nil {
			return nil, err
		}
		next = max(since, Cursor(mark))
	}

	// Group rows into one patch per type, emitted in dependency order.
	// Clients apply updates in patch order and deletes in reverse patch
	// order to respect their local foreign keys.
	grouped := make(map[string]*Patch)
	for _, row := range merged {
		p, exists := grouped[row.typ]
		if !exists {
			p = &Patch{ID: uuid.NewV7(), Type: row.typ}
			grouped[row.typ] = p
		}
		if row.Deleted {
			p.Delete = append(p.Delete, row.ID)
		} else {
			p.Update = append(p.Update, row.Data)
		}
	}

	patches := make([]Patch, 0, len(grouped))
	for _, typ := range order {
		if p, exists := grouped[typ]; exists {
			patches = append(patches, *p)
		}
	}

	return &Response{Patches: patches, Next: next, More: more}, nil
}
