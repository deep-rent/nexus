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
	"slices"

	"uuid"

	"github.com/deep-rent/nexus/dat/diff/hlc"
	"github.com/deep-rent/nexus/dat/valid"
	"github.com/deep-rent/nexus/sys/log"
)

// Engine orchestrates the bidirectional sync pipeline: it ingests change
// sets and compiles patch feeds within a single transaction per request.
type Engine[Tx any] struct {
	store Store[Tx]
	reg   *Registry[Tx]
	cfg   config
}

// New creates a sync engine around the given store and model registry.
// It panics if store or registry is nil, no models are registered,
// or their declared relationships are cyclic or dangling (programmer
// error).
func New[Tx any](
	store Store[Tx],
	reg *Registry[Tx],
	opts ...Option,
) *Engine[Tx] {
	if store == nil {
		panic("store is required")
	}
	if reg == nil || len(reg.entries) == 0 {
		panic("registry with at least one model is required")
	}
	reg.order()  // surface cycles and dangling references now
	reg.verify() // surface handler/registry misconfiguration now

	cfg := config{
		logger:     log.Discard(),
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

// Get returns the live version of a single document by model name and ID,
// applying the same visibility rules as the patch feed: the caller's own
// documents, their teams' documents, and foreign personal documents shared
// with any of their teams. It returns [ErrUnknownModel] for unregistered
// models, [ErrUnsupportedModel] when the model's handler does not implement
// [Reader], and [ErrNotFound] when the document is absent, deleted, or not
// visible to the scope (indistinguishable by design).
//
// Unlike Sync, Get acquires no advisory locks: the scope locks exist to
// keep the barrier/scan window of cursor pagination sound, and a point read
// carries no cursor. A read-committed snapshot of the single row is all it
// needs.
func (e *Engine[Tx]) Get(
	ctx context.Context,
	scope Scope,
	model string,
	id uuid.UUID,
) (*Document, error) {
	entry, known := e.reg.lookup(model)
	if !known {
		return nil, ErrUnknownModel
	}
	reader, ok := entry.handler.(Reader[Tx])
	if !ok {
		return nil, ErrUnsupportedModel
	}

	var doc *Document
	err := e.store.Exec(ctx, func(ctx context.Context, tx Tx) error {
		v, found, err := reader.Read(ctx, tx, scope, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		doc = &Document{Model: model, Time: Stamp(v.Time), Data: v.Data}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// change extends [Op] with ingestion bookkeeping.
type change struct {
	Op
	model    string
	mutation uuid.UUID // client-assigned mutation id
	parent   uuid.UUID // referenced ownership parent (child types only)
	child    bool      // identity derives from the parent chain
	resolved bool      // identity in Meta is final
	stored   *Meta     // identity of the targeted stored row, if any
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
			e.cfg.logger.Warn(ctx, "prefilter failed", log.Error(err))
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
			shared, exclusive, err := e.assemble(
				ctx, tx, scope, winners, extra, true,
			)
			if err != nil {
				return err
			}
			if err := e.store.Lock(ctx, tx, shared, exclusive); err != nil {
				return err
			}

			// Re-resolve under the locks; any WRITE key outside the held
			// exclusive set means a concurrent ownership change slipped in
			// between resolution and locking. The verify pass re-derives the
			// mutable inputs (stored identities and child ownership chains)
			// that could still point outside the held set, but skips the
			// grant resolution: its owners are already exclusively held, so
			// their grants cannot change under the lock (see assemble).
			_, verify, err := e.assemble(
				ctx, tx, scope, winners, extra, false,
			)
			if err != nil {
				return err
			}
			held := make(map[uuid.UUID]struct{}, len(exclusive))
			for _, k := range exclusive {
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
			e.cfg.logger.Warn(ctx, "prefilter mark failed", log.Error(err))
		}
	}

	e.cfg.logger.Info(ctx, "sync completed",
		log.UUID("user", scope.UserID),
		log.Int("received", len(req.Changes)),
		log.Int("applied", len(winners)),
		log.Int("patches", len(resp.Patches)),
		log.Bool("more", resp.More),
	)
	return resp, nil
}

// screen validates and authorizes the raw changes without touching storage.
// It decodes each payload envelope, enforces scope on root identities,
// validates document payloads, and merges every timestamp into the engine
// clock. All rejections are collected into a single [Error], keyed by
// mutation ID, so the client can repair its queue in one pass.
func (e *Engine[Tx]) screen(
	scope Scope,
	raw []Change,
) ([]*change, error) {
	rejected := &Error{}

	// Mutation IDs must be unique within a request: idempotent dedup keys on
	// the mutation ID, so a reused ID would let two documents share one
	// dedup record. A duplicate is a client contract violation.
	seen := make(map[uuid.UUID]struct{}, len(raw))

	changes := make([]*change, 0, len(raw))
	for i := range raw {
		in := &raw[i]

		// Structural sanity first, so every per-change failure funnels
		// through the same per-mutation rejection format.
		if in.ID == uuid.Nil() || in.ID[6]>>4 != 7 {
			rejected.reject(in.ID, Cause{Code: CodeInvalid, Fields: valid.Error{
				"id": {"must be a valid UUIDv7"},
			}})
			continue
		}
		if _, dup := seen[in.ID]; dup {
			rejected.reject(in.ID, Cause{Code: CodeInvalid, Fields: valid.Error{
				"id": {"must be unique within the request"},
			}})
			continue
		}
		seen[in.ID] = struct{}{}
		if in.Action != ActionUpsert && in.Action != ActionDelete {
			rejected.reject(in.ID, Cause{Code: CodeInvalid, Fields: valid.Error{
				"action": {"must be one of upsert, delete"},
			}})
			continue
		}
		if len(in.Data) == 0 {
			rejected.reject(in.ID, Cause{Code: CodeInvalid, Fields: valid.Error{
				"data": {"must not be empty"},
			}})
			continue
		}
		if in.Time == 0 || in.Time > hlc.Max {
			rejected.reject(in.ID, Cause{Code: CodeInvalid, Fields: valid.Error{
				"time": {"must be between 1 and 2^53 - 1"},
			}})
			continue
		}

		entry, known := e.reg.lookup(in.Model)
		if !known {
			rejected.reject(in.ID, Cause{Code: CodeUnknownModel})
			continue
		}

		c := &change{
			Action:   in.Action,
			Time:     hlc.Time(in.Time),
			model:    in.Model,
			mutation: in.ID,
		}
		if in.Action == ActionUpsert {
			c.Data = in.Data
		}

		if entry.root {
			var meta Meta
			if err := json.Unmarshal(in.Data, &meta); err != nil ||
				meta.ID == uuid.Nil() {
				rejected.reject(
					in.ID,
					Cause{Code: CodeInvalid, Fields: valid.Error{
						"data": {"must carry a valid document envelope"},
					}},
				)
				continue
			}
			// The typed decode already enforces UUID format; only a
			// missing owner remains to reject.
			if meta.UserID == uuid.Nil() {
				rejected.reject(
					in.ID,
					Cause{Code: CodeInvalid, Fields: valid.Error{
						"data": {"owner must not be empty"},
					}},
				)
				continue
			}
			c.Meta = meta
			c.resolved = true

			// Payload identity is never trusted: it must lie inside the
			// caller's scope, and shares may only be issued by their owner.
			if !scope.Allows(meta.UserID, meta.TeamID) ||
				(in.Model == ModelShare && meta.UserID != scope.UserID) {
				rejected.reject(in.ID, Cause{Code: CodeForbidden})
				continue
			}
		} else {
			id, parent, err := envelope(in.Data, entry.ownerVia)
			if err != nil {
				rejected.reject(
					in.ID,
					Cause{Code: CodeInvalid, Fields: valid.Error{
						"data": {"must carry a valid document envelope"},
					}},
				)
				continue
			}
			c.Meta.ID = id
			c.parent = parent
			c.child = true
			if in.Action == ActionUpsert && parent == uuid.Nil() {
				rejected.reject(
					in.ID,
					Cause{Code: CodeInvalid, Fields: valid.Error{
						"data": {fmt.Sprintf(
							"must reference a parent document via %q",
							entry.ownerVia,
						)},
					}},
				)
				continue
			}
		}

		if in.Action == ActionUpsert {
			if verr := entry.check(in.Data); verr != nil {
				rejected.reject(in.ID, Cause{Code: CodeInvalid, Fields: verr})
				continue
			}
		}

		if _, err := e.cfg.clock.Update(hlc.Time(in.Time)); err != nil {
			// Both clock failures are attributable to this one change's
			// timestamp, so they degrade to a per-mutation rejection rather
			// than failing the whole request: drift means the stamp is too
			// far ahead, overflow means too many same-second mutations.
			rejected.reject(in.ID, Cause{Code: CodeDrift})
			continue
		}

		changes = append(changes, c)
	}

	if err := rejected.or(); err != nil {
		return nil, err
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
		model string
		id    uuid.UUID
	}
	best := make(map[key]*change, len(changes))
	for _, c := range changes {
		k := key{model: c.model, id: c.Meta.ID}
		cur, exists := best[k]
		if !exists || c.Time > cur.Time ||
			(c.Time == cur.Time && c.mutation.Compare(cur.mutation) > 0) {
			best[k] = c
		}
	}

	winners := make([]*change, 0, len(best))
	for _, c := range changes { // preserve request order for determinism
		if best[key{model: c.model, id: c.Meta.ID}] == c {
			winners = append(winners, c)
		}
	}
	return winners
}

// assemble computes the lock set of the request. Shared keys cover what the
// request only reads (the caller's scope, for feed visibility); exclusive
// keys cover everything it writes: payload identities, stored identities of
// targeted rows (a delete or team move must fence the row's PREVIOUS
// audience too), resolved child roots, and — for writes touching personal
// documents — the teams currently granted by the owning user, keeping
// grant-based readers inside the fence. Extra keys carry over from a
// drifted previous attempt.
func (e *Engine[Tx]) assemble(
	ctx context.Context,
	tx Tx,
	scope Scope,
	winners []*change,
	extra map[uuid.UUID]struct{},
	grants bool,
) (shared, exclusive []uuid.UUID, err error) {
	if err := e.resolve(ctx, tx, winners); err != nil {
		return nil, nil, err
	}

	write := make(map[uuid.UUID]struct{})
	owners := make(
		map[uuid.UUID]struct{},
	) // owners whose personal docs are written
	include := func(userID, teamID uuid.UUID) {
		write[userID] = struct{}{}
		if teamID != uuid.Nil() {
			write[teamID] = struct{}{}
		} else {
			owners[userID] = struct{}{}
		}
	}
	for _, c := range winners {
		if c.resolved {
			include(c.Meta.UserID, c.Meta.TeamID)
		}
		if c.stored != nil {
			include(c.stored.UserID, c.stored.TeamID)
		}
		// A landing grant re-sequences the owner's personal documents, so
		// share writes fence like personal-document writes of the owner.
		if c.model == ModelShare && c.resolved {
			owners[c.Meta.UserID] = struct{}{}
		}
	}

	// Personal documents may be visible to teams through live grants; their
	// members' feeds fence on the team key, so writers must hold it too.
	//
	// The verify pass (grants == false) skips this resolution entirely. Every
	// owner in this set writes a personal document, so it is already in the
	// exclusive set the pass-1 lock holds; a concurrent grant change for such
	// an owner would itself need that owner's exclusive key and therefore
	// cannot land under our lock, freezing the owner's grants for the txn.
	// The grant-derived team keys resolved by pass 1 thus stay complete and
	// valid, and re-deriving them here would only repeat the shares scan. Any
	// owner that newly appears under the lock is caught by its own key in the
	// drift check below, before its grants could ever matter.
	if grants && len(owners) > 0 {
		ids := make([]uuid.UUID, 0, len(owners))
		for owner := range owners {
			ids = append(ids, owner)
		}
		slices.SortFunc(ids, func(a, b uuid.UUID) int { return a.Compare(b) })
		granted, err := e.store.Grants(ctx, tx, ids)
		if err != nil {
			return nil, nil, err
		}
		for _, teams := range granted {
			for _, team := range teams {
				write[team] = struct{}{}
			}
		}
	}

	for k := range extra {
		write[k] = struct{}{}
	}

	read := make(map[uuid.UUID]struct{})
	if _, ok := write[scope.UserID]; !ok {
		read[scope.UserID] = struct{}{}
	}
	for _, team := range scope.Teams {
		if _, ok := write[team]; !ok {
			read[team] = struct{}{}
		}
	}

	shared = make([]uuid.UUID, 0, len(read))
	for k := range read {
		shared = append(shared, k)
	}
	exclusive = make([]uuid.UUID, 0, len(write))
	for k := range write {
		exclusive = append(exclusive, k)
	}
	compare := func(a, b uuid.UUID) int { return a.Compare(b) }
	slices.SortFunc(shared, compare)
	slices.SortFunc(exclusive, compare)
	return shared, exclusive, nil
}

// resolve walks child ownership chains until every change carries its root
// identity: in-batch parents are chased transitively, everything else is
// looked up through the parent type's handler.
func (e *Engine[Tx]) resolve(
	ctx context.Context,
	tx Tx,
	winners []*change,
) error {
	// Stored and child-derived identities come from mutable rows and may
	// drift between attempts, so they are re-derived on every call; root
	// payload identities are immutable and stay final.
	for _, c := range winners {
		c.stored = nil
		if c.child {
			c.resolved = false
			c.Meta.UserID = uuid.Nil()
			c.Meta.TeamID = uuid.Nil()
		}
	}

	// Resolve the stored identity of every targeted row. Deletes and team
	// moves must fence the row's previous audience, so its current identity
	// belongs to the lock set even when the payload says otherwise.
	targets := make(map[string][]uuid.UUID)
	for _, c := range winners {
		targets[c.model] = append(targets[c.model], c.Meta.ID)
	}
	for model, ids := range targets {
		entry, _ := e.reg.lookup(model)
		metas, err := entry.handler.Resolve(ctx, tx, ids)
		if err != nil {
			return err
		}
		for _, c := range winners {
			if c.model != model {
				continue
			}
			if meta, ok := metas[c.Meta.ID]; ok {
				c.stored = &meta

				// A child delete's identity is the stored row itself.
				if c.child && c.Action == ActionDelete &&
					c.parent == uuid.Nil() {
					c.Meta.UserID = meta.UserID
					c.Meta.TeamID = meta.TeamID
					c.resolved = true
				}
			}
		}
	}

	// Index in-batch upserts so children can inherit identity from parents
	// created in the same request.
	batch := make(map[string]map[uuid.UUID]*change)
	for _, c := range winners {
		if c.Action != ActionUpsert {
			continue
		}
		if batch[c.model] == nil {
			batch[c.model] = make(map[uuid.UUID]*change)
		}
		batch[c.model][c.Meta.ID] = c
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
			entry, _ := e.reg.lookup(c.model)

			if c.Action == ActionDelete && c.parent == uuid.Nil() {
				continue // never-seen child delete: dropped later
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
		for model, ids := range pending {
			entry, ok := e.reg.lookup(model)
			if !ok {
				continue
			}
			// Siblings share parents, so the batch may carry duplicates.
			slices.SortFunc(ids, func(a, b uuid.UUID) int {
				return a.Compare(b)
			})
			metas, err := entry.handler.Resolve(ctx, tx, slices.Compact(ids))
			if err != nil {
				return err
			}
			found[model] = metas
		}

		for _, c := range winners {
			if c.resolved {
				continue
			}
			entry, _ := e.reg.lookup(c.model)

			if c.Action == ActionDelete && c.parent == uuid.Nil() {
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
	rejected := &Error{}
	for _, c := range winners {
		if !c.resolved && c.Action == ActionUpsert {
			rejected.reject(c.mutation, Cause{Code: CodeOrphaned})
		}
	}
	return rejected.or()
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

	// Authorize resolved child identities: the root a child hangs off must
	// itself be accessible to the caller.
	rejected := &Error{}
	for _, c := range winners {
		if c.resolved && !scope.Allows(c.Meta.UserID, c.Meta.TeamID) {
			rejected.reject(c.mutation, Cause{Code: CodeForbidden})
		}
	}
	if err := rejected.or(); err != nil {
		return nil, err
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
	writes := false
	for _, c := range winners {
		if _, ok := fresh[c.mutation]; !ok {
			continue
		}
		if !c.resolved {
			continue // delete of a never-seen child document
		}
		switch c.Action {
		case ActionUpsert:
			upserts[c.model] = append(upserts[c.model], c.Op)
			writes = true
		case ActionDelete:
			deletes[c.model] = append(deletes[c.model], c.Op)
			writes = true
		}
	}

	// The feed window ceiling. When this request applies at least one write,
	// the Barrier consumes one sequence value up front: every row this
	// request writes then takes a sequence strictly above it, so scanning
	// below it fences the request's own writes out of its feed. When there
	// is genuinely nothing to write (an empty push, or a pure replay whose
	// claims all lost), that fence is moot, so we spend no sequence value
	// and use the Watermark (the highest sequence assigned so far) as the
	// ceiling instead — a no-op poll must not advance the global sequence.
	// The exclusive upper bound is watermark + 1 so the scan still includes
	// the row sitting at the watermark. Concurrent in-scope writers hold the
	// scope keys we lock, so no visible row can appear past the watermark
	// while we read.
	var barrier int64
	if writes {
		barrier, err = e.store.Barrier(ctx, tx)
		if err != nil {
			return nil, err
		}
	} else {
		mark, err := e.store.Watermark(ctx, tx)
		if err != nil {
			return nil, err
		}
		barrier = mark + 1
	}

	order := e.reg.order()

	// Parents before children for upserts, children before parents for
	// deletes: mirrors client-side foreign key constraints.
	for _, model := range order {
		if ops := upserts[model]; len(ops) > 0 {
			entry, _ := e.reg.lookup(model)
			if err := entry.handler.Upsert(ctx, tx, scope, ops); err != nil {
				return nil, err
			}
		}
	}
	for _, model := range slices.Backward(order) {
		if ops := deletes[model]; len(ops) > 0 {
			entry, _ := e.reg.lookup(model)
			if err := entry.handler.Delete(ctx, tx, scope, ops); err != nil {
				return nil, err
			}
		}
	}

	resp, err := e.feed(ctx, tx, scope, req.Since, barrier, limit)
	if err != nil {
		return nil, err
	}

	// Tombstone pruning runs outside the advisory locks and may advance the
	// floor while this transaction scans (read committed: every statement
	// sees a fresh snapshot). Re-checking after the scan guarantees the page
	// missed no pruned deletion: had pruning removed a tombstone from the
	// window, the floor now lies above since.
	floor, err = e.store.Floor(ctx, tx)
	if err != nil {
		return nil, err
	}
	if req.Since > 0 && int64(req.Since) < floor {
		return nil, &ResyncError{Floor: Cursor(floor)}
	}
	return resp, nil
}

// version tags a fetched row with its model during feed assembly.
type version struct {
	Version
	model string
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

	// Each model contributes at most limit+1 rows; after every fetch the
	// merged set is pruned back to the limit+1 lowest sequences and the
	// window ceiling tightened, so memory stays bounded at ~2x limit and
	// later scans shrink. Rows above the (limit+1)-th sequence can never
	// appear in this page nor affect More.
	var merged []version
	until := barrier
	for _, model := range order {
		entry, _ := e.reg.lookup(model)
		rows, err := entry.handler.Fetch(ctx, tx, scope, Window{
			Since: int64(since),
			Until: until,
			Limit: limit + 1,
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			merged = append(merged, version{Version: row, model: model})
		}
		if len(merged) > limit+1 {
			slices.SortFunc(merged, func(a, b version) int {
				return cmp.Compare(a.Seq, b.Seq)
			})
			merged = merged[:limit+1]
			until = merged[limit].Seq + 1
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
		p, exists := grouped[row.model]
		if !exists {
			p = &Patch{ID: uuid.NewV7(), Model: row.model}
			grouped[row.model] = p
		}
		if row.Deleted {
			p.Delete = append(p.Delete, Deletion{
				ID:   row.ID,
				Time: Stamp(row.Time),
			})
		} else {
			p.Update = append(p.Update, Row{
				Time: Stamp(row.Time),
				Data: row.Data,
			})
		}
	}

	patches := make([]Patch, 0, len(grouped))
	for _, model := range order {
		if p, exists := grouped[model]; exists {
			patches = append(patches, *p)
		}
	}

	return &Response{Patches: patches, Next: next, More: more}, nil
}
