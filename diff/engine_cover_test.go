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

package diff_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/diff/driver/mock"
	"github.com/deep-rent/nexus/internal/hlc"
	"github.com/deep-rent/nexus/valid"
)

// prefilter is a controllable [diff.Prefilter] for exercising the fast-path
// deduplication branch of the engine.
type prefilter struct {
	drop     map[uuid.UUID]struct{} // ids reported as already-seen
	filErr   error
	markErr  error
	marked   []uuid.UUID
	filtered bool
}

func (p *prefilter) Filter(
	_ context.Context,
	ids []uuid.UUID,
) ([]uuid.UUID, error) {
	p.filtered = true
	if p.filErr != nil {
		return nil, p.filErr
	}
	fresh := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, seen := p.drop[id]; !seen {
			fresh = append(fresh, id)
		}
	}
	return fresh, nil
}

func (p *prefilter) Mark(_ context.Context, ids []uuid.UUID) error {
	p.marked = append(p.marked, ids...)
	return p.markErr
}

// metaID extracts the document id from an upsert change payload.
func metaID(t *testing.T, c diff.Change) uuid.UUID {
	t.Helper()
	var m struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(c.Data, &m); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	return m.ID
}

func TestEngine_Now(t *testing.T) {
	t.Parallel()

	f := setup()
	t1 := f.engine.Now()
	t2 := f.engine.Now()
	if t1 == 0 || t2 <= t1 {
		t.Errorf("got %d then %d; want strictly increasing non-zero stamps",
			t1, t2)
	}
}

func TestEngine_Options(t *testing.T) {
	t.Parallel()

	// The options must clamp and default correctly, observable through
	// behavior: a limit above the max is capped, and nil options are no-ops.
	store := mock.New()
	assets := mock.NewHandler(store)
	reg := diff.NewRegistry[*mock.Tx]()
	reg.Register[asset]("asset", assets, diff.Root())

	engine := diff.New(store, reg,
		diff.WithLogger(nil),            // ignored
		diff.WithLogger(slog.Default()), // applied
		diff.WithClock(nil),             // ignored
		diff.WithClock(hlc.New(nil)),    // applied
		diff.WithPrefilter(nil),         // ignored
		diff.WithMaxChanges(0),          // ignored (non-positive)
		diff.WithMaxPatches(2),          // applied
		diff.WithDefaultLimit(0),        // ignored (non-positive)
	)

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	var changes []diff.Change
	for range 5 {
		changes = append(
			changes,
			upsert(
				"asset",
				assetDoc(uuid.NewV7(), owner, uuid.Nil()),
				stamp(1),
			),
		)
	}
	if _, err := engine.Sync(t.Context(), scope,
		&diff.Request{Changes: changes}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	// A fresh device requesting limit 1000 must be capped at WithMaxPatches(2).
	res, err := engine.Sync(t.Context(), scope,
		&diff.Request{Limit: 1000})
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	total := 0
	for _, p := range res.Patches {
		total += len(p.Update)
	}
	if total > 2 {
		t.Errorf("got %d rows; want at most the capped 2", total)
	}
	if !res.More {
		t.Error("more: got false; want true (capped page leaves a backlog)")
	}
}

func TestEngine_Sync_Prefilter(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	t.Run("drops already-seen ids", func(t *testing.T) {
		t.Parallel()
		seen := upsert(
			"asset",
			assetDoc(uuid.NewV7(), owner, uuid.Nil()),
			stamp(1),
		)
		fresh := upsert(
			"asset",
			assetDoc(uuid.NewV7(), owner, uuid.Nil()),
			stamp(2),
		)

		pf := &prefilter{drop: map[uuid.UUID]struct{}{seen.ID: {}}}
		f2 := setup(diff.WithPrefilter(pf))
		if _, err := f2.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{seen, fresh},
		}); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if !pf.filtered {
			t.Error("Filter should have been consulted")
		}
		// Only the fresh mutation is applied and marked.
		if _, alive := f2.assets.Rows()[metaID(t, seen)]; alive {
			t.Error("prefiltered change should not have been applied")
		}
		if _, alive := f2.assets.Rows()[metaID(t, fresh)]; !alive {
			t.Error("fresh change should have been applied")
		}
		if len(pf.marked) != 1 || pf.marked[0] != fresh.ID {
			t.Errorf("marked: got %v; want [%v]", pf.marked, fresh.ID)
		}
	})

	t.Run("filter error falls back to full apply", func(t *testing.T) {
		t.Parallel()
		pf := &prefilter{filErr: errors.New("valkey down")}
		f := setup(diff.WithPrefilter(pf),
			diff.WithLogger(slog.New(slog.DiscardHandler)))
		c := upsert(
			"asset",
			assetDoc(uuid.NewV7(), owner, uuid.Nil()),
			stamp(1),
		)
		if _, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{c},
		}); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		// The change is applied despite the prefilter failure.
		if _, alive := f.assets.Rows()[metaID(t, c)]; !alive {
			t.Error("change should have been applied on prefilter failure")
		}
	})

	t.Run("mark error is swallowed", func(t *testing.T) {
		t.Parallel()
		pf := &prefilter{markErr: errors.New("valkey down")}
		f := setup(diff.WithPrefilter(pf),
			diff.WithLogger(slog.New(slog.DiscardHandler)))
		c := upsert(
			"asset",
			assetDoc(uuid.NewV7(), owner, uuid.Nil()),
			stamp(1),
		)
		if _, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{c},
		}); err != nil {
			t.Errorf("mark failure should not fail the sync: %v", err)
		}
	})
}

func TestEngine_Sync_DriftRetry(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	teamA := uuid.NewV7()
	teamB := uuid.NewV7()
	scope := diff.Scope{UserID: owner, Teams: []uuid.UUID{teamA, teamB}}

	t.Run("recovers after one retry", func(t *testing.T) {
		t.Parallel()
		f := setup()

		// Seed a parent asset in team A.
		assetID := uuid.NewV7()
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert("asset", assetDoc(assetID, owner, teamA), stamp(1)),
		}})

		// While the engine holds locks derived from team A, a concurrent
		// change moves the parent to team B exactly once. The first verify
		// pass sees the drift and retries; the second attempt locks team B
		// and succeeds.
		moved := false
		f.store.OnLock = func() {
			if moved {
				return
			}
			moved = true
			_ = f.assets.Upsert(t.Context(), &mock.Tx{}, scope, []diff.Op{{
				Meta:   diff.Meta{ID: assetID, UserID: owner, TeamID: teamB},
				Action: diff.ActionUpsert,
				Time:   stamp(10),
				Data:   assetDoc(assetID, owner, teamB),
			}})
		}

		contractID := uuid.NewV7()
		_, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{
				upsert("contract", contractDoc(contractID, assetID), stamp(2)),
			},
		})
		if err != nil {
			t.Fatalf("should have recovered via retry, got: %v", err)
		}
		if _, alive := f.contracts.Rows()[contractID]; !alive {
			t.Error("child should have been applied on the retry")
		}
	})

	t.Run("gives up with ErrConflict", func(t *testing.T) {
		t.Parallel()
		f := setup()
		assetID := uuid.NewV7()
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert("asset", assetDoc(assetID, owner, teamA), stamp(1)),
		}})

		// The parent's team flip-flops on every lock acquisition, always
		// away from what the current attempt resolved (seed is team A), so
		// the verify pass detects drift on every attempt and the engine
		// gives up. n=1 -> B (drift off A), n=2 -> A (drift off B).
		n := 0
		f.store.OnLock = func() {
			n++
			team := teamB
			if n%2 == 0 {
				team = teamA
			}
			_ = f.assets.Upsert(t.Context(), &mock.Tx{}, scope, []diff.Op{{
				Meta:   diff.Meta{ID: assetID, UserID: owner, TeamID: team},
				Action: diff.ActionUpsert,
				Time:   f.engine.Now(),
				Data:   assetDoc(assetID, owner, team),
			}})
		}

		_, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{
				upsert(
					"contract",
					contractDoc(uuid.NewV7(), assetID),
					stamp(2),
				),
			},
		})
		if !errors.Is(err, diff.ErrConflict) {
			t.Fatalf("got error %v; want ErrConflict", err)
		}
	})
}

func TestEngine_Sync_ConcurrentPrune(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	// Seed a document so the feed scan runs (and triggers OnFetch).
	sync(t, f, scope, &diff.Request{Changes: []diff.Change{
		upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1)),
	}})

	// A prune advances the floor above the request cursor while the feed
	// scans; the post-feed recheck must convert this into a resync.
	f.assets.OnFetch = func() {
		f.store.SetFloor(1_000_000)
		f.assets.OnFetch = nil // fire once
	}

	_, err := f.engine.Sync(t.Context(), scope, &diff.Request{Since: 5})
	var rerr *diff.ResyncError
	if !errors.As(err, &rerr) {
		t.Fatalf("got error %v; want ResyncError", err)
	}
	if rerr.Floor != 1_000_000 {
		t.Errorf("floor: got %d; want 1000000", rerr.Floor)
	}
}

func TestEngine_Sync_StoreErrors(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	boom := errors.New("store down")

	req := func() *diff.Request {
		return &diff.Request{Changes: []diff.Change{
			upsert(
				"asset",
				assetDoc(uuid.NewV7(), owner, uuid.Nil()),
				stamp(1),
			),
		}}
	}

	tests := []struct {
		name   string
		break_ func(s *mock.Store)
	}{
		{"exec", func(s *mock.Store) { s.ErrExec = boom }},
		{"lock", func(s *mock.Store) { s.ErrLock = boom }},
		{"floor", func(s *mock.Store) { s.ErrFloor = boom }},
		{"barrier", func(s *mock.Store) { s.ErrBarrier = boom }},
		{"claim", func(s *mock.Store) { s.ErrClaim = boom }},
		{"grants", func(s *mock.Store) { s.ErrGrants = boom }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := setup()
			tt.break_(f.store)
			if _, err := f.engine.Sync(
				t.Context(), scope, req()); !errors.Is(err, boom) {
				t.Errorf("got error %v; want %v", err, boom)
			}
		})
	}
}

func TestEngine_Sync_ChildEnvelopeErrors(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	t.Run("malformed child payload", func(t *testing.T) {
		t.Parallel()
		f := setup()
		c := upsert(
			"contract",
			jsontext.Value(`{"id":`),
			stamp(1),
		) // broken JSON
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})
		rejectedWith(t, err, c.ID, diff.CodeInvalid)
	})

	t.Run("child missing id", func(t *testing.T) {
		t.Parallel()
		f := setup()
		c := upsert(
			"contract",
			jsontext.Value(
				`{"asset_id":"`+uuid.NewV7().String()+`"}`,
			),
			stamp(1),
		)
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})
		rejectedWith(t, err, c.ID, diff.CodeInvalid)
	})

	t.Run("child upsert without parent ref", func(t *testing.T) {
		t.Parallel()
		f := setup()
		c := upsert("contract",
			jsontext.Value(`{"id":"`+uuid.NewV7().String()+`"}`), stamp(1))
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})
		rejectedWith(t, err, c.ID, diff.CodeInvalid)
	})

	t.Run("delete of never-seen child is dropped", func(t *testing.T) {
		t.Parallel()
		f := setup()
		// A delete of a child with no stored row and no parent ref resolves
		// to nothing and is silently dropped, leaving an empty successful
		// sync rather than a rejection.
		c := remove("contract",
			jsontext.Value(`{"id":"`+uuid.NewV7().String()+`"}`), stamp(1))
		res, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if len(res.Patches) != 0 {
			t.Errorf("got %d patches; want 0", len(res.Patches))
		}
	})
}

func TestShare_Validate(t *testing.T) {
	t.Parallel()

	user := uuid.NewV7()
	team := uuid.NewV7()
	tests := []struct {
		name  string
		share diff.Share
		ok    bool
	}{
		{"valid", diff.Share{UserID: user, TeamID: team}, true},
		{"empty team", diff.Share{UserID: user}, false},
		{"empty user", diff.Share{TeamID: team}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := valid.Test(&tt.share)
			if tt.ok && err != nil {
				t.Errorf("should not have returned an error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Error("should have returned a validation error")
			}
		})
	}
}

func TestEngine_Sync_DuplicateMutationID(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	// Two changes sharing one mutation ID: the second is rejected as
	// invalid, protecting the idempotency dedup granularity.
	id := uuid.NewV7()
	a := upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1))
	a.ID = id
	b := upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(2))
	b.ID = id

	_, err := f.engine.Sync(t.Context(), scope,
		&diff.Request{Changes: []diff.Change{a, b}})
	cause := rejectedWith(t, err, id, diff.CodeInvalid)
	if _, found := cause.Fields["id"]; !found {
		t.Errorf("got fields %v; want failure on %q", cause.Fields, "id")
	}
}

func TestEngine_Sync_LogicalOverflow(t *testing.T) {
	t.Parallel()

	// A clock whose logical counter is exhausted for the change's second
	// yields a per-change drift rejection, not a whole-request 500.
	base := uint64(1_700_000_000)
	clock := hlc.New(func() time.Time { return time.Unix(int64(base), 0) })
	f := setup(diff.WithClock(clock))

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	// A remote stamp in the same second with the counter already maxed
	// forces ErrLogicalOverflow inside clock.Update.
	overflow := diff.Stamp(hlc.Pack(base, (1<<20)-1))
	c := upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), overflow)

	_, err := f.engine.Sync(t.Context(), scope,
		&diff.Request{Changes: []diff.Change{c}})
	rejectedWith(t, err, c.ID, diff.CodeDrift)
}

func TestRegister_SelfOwnerPanics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func(r *diff.Registry[*mock.Tx])
	}{
		{
			name: "self owner",
			fn: func(r *diff.Registry[*mock.Tx]) {
				r.Register[asset]("asset", mock.NewHandler(mock.New()),
					diff.Owner("asset", "self_id"))
			},
		},
		{
			name: "self parent",
			fn: func(r *diff.Registry[*mock.Tx]) {
				r.Register[asset]("asset", mock.NewHandler(mock.New()),
					diff.Root(), diff.Parents("asset"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("should have panicked")
				}
			}()
			tt.fn(diff.NewRegistry[*mock.Tx]())
		})
	}
}

// feedOnly wraps a handler while hiding its optional interfaces, modeling a
// custom handler that does not support point reads.
type feedOnly struct {
	diff.Handler[*mock.Tx]
}

func TestEngine_Get(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	id := uuid.NewV7()

	at := stamp(1)
	if _, err := f.engine.Sync(t.Context(), scope, &diff.Request{
		Changes: []diff.Change{upsert("asset", assetDoc(id, owner,
			uuid.Nil()), at)},
	}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	doc, err := f.engine.Get(t.Context(), scope, "asset", id)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if doc.Model != "asset" {
		t.Errorf("model: got %q; want %q", doc.Model, "asset")
	}
	if doc.Time != at {
		t.Errorf("time: got %d; want %d", doc.Time, at)
	}
	var payload struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(doc.Data, &payload); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if payload.ID != id {
		t.Errorf("data id: got %v; want %v", payload.ID, id)
	}

	// A foreign caller cannot distinguish the document from a missing one.
	foreign := diff.Scope{UserID: uuid.NewV7()}
	if _, err := f.engine.Get(
		t.Context(), foreign, "asset", id,
	); !errors.Is(err, diff.ErrNotFound) {
		t.Errorf("foreign get: got %v; want ErrNotFound", err)
	}

	// Absent documents are not found.
	if _, err := f.engine.Get(
		t.Context(), scope, "asset", uuid.NewV7(),
	); !errors.Is(err, diff.ErrNotFound) {
		t.Errorf("absent get: got %v; want ErrNotFound", err)
	}

	// Deleted documents are not found.
	if _, err := f.engine.Sync(t.Context(), scope, &diff.Request{
		Changes: []diff.Change{remove("asset", assetDoc(id, owner,
			uuid.Nil()), stamp(2))},
	}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if _, err := f.engine.Get(
		t.Context(), scope, "asset", id,
	); !errors.Is(err, diff.ErrNotFound) {
		t.Errorf("deleted get: got %v; want ErrNotFound", err)
	}

	// Unregistered models are unknown.
	if _, err := f.engine.Get(
		t.Context(), scope, "vehicle", id,
	); !errors.Is(err, diff.ErrUnknownModel) {
		t.Errorf("unknown model: got %v; want ErrUnknownModel", err)
	}
}

func TestEngine_Get_Errors(t *testing.T) {
	t.Parallel()

	t.Run("unsupported model", func(t *testing.T) {
		t.Parallel()
		store := mock.New()
		reg := diff.NewRegistry[*mock.Tx]()
		reg.Register[asset]("asset",
			feedOnly{mock.NewHandler(store)}, diff.Root())
		engine := diff.New(store, reg)

		_, err := engine.Get(t.Context(), diff.Scope{UserID: uuid.NewV7()},
			"asset", uuid.NewV7())
		if !errors.Is(err, diff.ErrUnsupportedModel) {
			t.Errorf("got %v; want ErrUnsupportedModel", err)
		}
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()
		f := setup()
		boom := errors.New("boom")
		f.store.ErrExec = boom

		_, err := f.engine.Get(t.Context(), diff.Scope{UserID: uuid.NewV7()},
			"asset", uuid.NewV7())
		if !errors.Is(err, boom) {
			t.Errorf("got %v; want the injected store error", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		t.Parallel()
		f := setup()
		boom := errors.New("boom")
		f.assets.ErrRead = boom

		_, err := f.engine.Get(t.Context(), diff.Scope{UserID: uuid.NewV7()},
			"asset", uuid.NewV7())
		if !errors.Is(err, boom) {
			t.Errorf("got %v; want the injected read error", err)
		}
	})
}
