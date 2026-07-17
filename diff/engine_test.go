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
	"fmt"
	"slices"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/diff/driver/mock"
	"github.com/deep-rent/nexus/internal/hlc"
	"github.com/deep-rent/nexus/valid"
)

// recorder wraps a handler and appends "name:action" entries to a shared
// log, capturing the cross-handler order of engine calls.
type recorder struct {
	*mock.Handler
	name string
	log  *[]string
}

func (r *recorder) Upsert(
	ctx context.Context, tx *mock.Tx, scope diff.Scope, ops []diff.Op,
) error {
	*r.log = append(*r.log, r.name+":upsert")
	return r.Handler.Upsert(ctx, tx, scope, ops)
}

func (r *recorder) Delete(
	ctx context.Context, tx *mock.Tx, scope diff.Scope, ops []diff.Op,
) error {
	*r.log = append(*r.log, r.name+":delete")
	return r.Handler.Delete(ctx, tx, scope, ops)
}

// asset is a root document model with payload validation.
type asset struct {
	ID     uuid.UUID `json:"id"`
	UserID uuid.UUID `json:"user_id"`
	TeamID uuid.UUID `json:"team_id,omitzero"`
	Name   string    `json:"name"`
}

func (a *asset) Validate(v *valid.Validator) {
	v.NotEmpty("name", a.Name)
}

// contract is a child document owned by an asset.
type contract struct {
	ID      uuid.UUID `json:"id"`
	AssetID uuid.UUID `json:"asset_id"`
}

// fixture wires an engine over the mock driver with an asset root type, a
// contract child type, and shares enabled.
type fixture struct {
	store     *mock.Store
	assets    *mock.Handler
	contracts *mock.Handler
	shares    *mock.Shares
	engine    *diff.Engine[*mock.Tx]
}

func setup(opts ...diff.Option) *fixture {
	f := &fixture{store: mock.New()}
	f.assets = mock.NewHandler(f.store)
	f.contracts = mock.NewHandler(f.store)
	f.shares = mock.NewShares(f.store)

	reg := diff.NewRegistry[*mock.Tx]()
	reg.Register[asset]("asset", f.assets, diff.Root())
	reg.Register[contract]("contract", f.contracts,
		diff.Owner("asset", "asset_id"))
	reg.RegisterShares(f.shares)

	f.engine = diff.New(f.store, reg, opts...)
	return f
}

// stamp builds an HLC timestamp n logical ticks into the current second.
func stamp(n uint64) diff.Stamp {
	return diff.Stamp(hlc.Pack(uint64(time.Now().Unix()), n))
}

func assetDoc(id uuid.UUID, owner, team uuid.UUID) jsontext.Value {
	doc := map[string]any{
		"id":      id.String(),
		"user_id": owner.String(),
		"name":    "doc",
	}
	if team != uuid.Nil() {
		doc["team_id"] = team.String()
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return jsontext.Value(b)
}

func contractDoc(id, assetID uuid.UUID) jsontext.Value {
	return jsontext.Value(fmt.Sprintf(
		`{"id":%q,"asset_id":%q}`, id.String(), assetID.String(),
	))
}

func upsert(model string, data jsontext.Value, at diff.Stamp) diff.Change {
	return diff.Change{
		ID:     uuid.NewV7(),
		Action: diff.ActionUpsert,
		Model:  model,
		Data:   data,
		Time:   at,
	}
}

func remove(model string, data jsontext.Value, at diff.Stamp) diff.Change {
	return diff.Change{
		ID:     uuid.NewV7(),
		Action: diff.ActionDelete,
		Model:  model,
		Data:   data,
		Time:   at,
	}
}

func sync(
	t *testing.T,
	f *fixture,
	scope diff.Scope,
	req *diff.Request,
) *diff.Response {
	t.Helper()
	res, err := f.engine.Sync(t.Context(), scope, req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	return res
}

// rejectedWith asserts that the provided error is a [*diff.Error] carrying the
// given code for the given mutation ID, and returns the recorded cause.
func rejectedWith(
	t *testing.T,
	err error,
	id uuid.UUID,
	code diff.Code,
) diff.Cause {
	t.Helper()
	rejected, ok := errors.AsType[*diff.Error](err)
	if !ok {
		t.Fatalf("got error %v; want *diff.Error", err)
	}
	cause, found := rejected.Causes[id]
	if !found {
		t.Fatalf("got causes %v; want entry for mutation %v",
			rejected.Causes, id)
	}
	if cause.Code != code {
		t.Fatalf("cause: got %q; want %q", cause.Code, code)
	}
	return cause
}

func TestEngine_Sync_PushPull(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	id := uuid.NewV7()

	// Device A pushes one asset; its own write must not echo back.
	res := sync(t, f, scope, &diff.Request{
		Changes: []diff.Change{
			upsert("asset", assetDoc(id, owner, uuid.Nil()), stamp(1)),
		},
	})
	if len(res.Patches) != 0 {
		t.Errorf("own writes should not echo; got %d patches",
			len(res.Patches))
	}
	if res.More {
		t.Error("more: got true; want false")
	}
	if res.Next <= 0 {
		t.Errorf("next: got %d; want positive cursor", res.Next)
	}

	// Device A syncs again from the returned cursor: still nothing.
	again := sync(t, f, scope, &diff.Request{Since: res.Next})
	if len(again.Patches) != 0 {
		t.Errorf("after catch-up: got %d patches; want 0", len(again.Patches))
	}

	// Device B (same user) starts fresh and receives the document.
	fresh := sync(t, f, scope, &diff.Request{})
	if len(fresh.Patches) != 1 {
		t.Fatalf("fresh sync: got %d patches; want 1", len(fresh.Patches))
	}
	p := fresh.Patches[0]
	if p.Model != "asset" {
		t.Errorf("patch model: got %q; want %q", p.Model, "asset")
	}
	if len(p.Update) != 1 || len(p.Delete) != 0 {
		t.Errorf("patch shape: got %d updates, %d deletes; want 1, 0",
			len(p.Update), len(p.Delete))
	}
}

func TestEngine_Sync_IdempotentReplay(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	id := uuid.NewV7()

	req := &diff.Request{
		Changes: []diff.Change{
			upsert("asset", assetDoc(id, owner, uuid.Nil()), stamp(1)),
		},
	}

	sync(t, f, scope, req)
	before := f.assets.Rows()

	// Byte-identical replay: rows and sequences must be untouched.
	sync(t, f, scope, req)
	after := f.assets.Rows()

	if len(before) != len(after) {
		t.Fatalf("row count changed: got %d; want %d",
			len(after), len(before))
	}
	for id, b := range before {
		a := after[id]
		if a.Seq != b.Seq {
			t.Errorf("row %v: seq changed from %d to %d (replay applied)",
				id, b.Seq, a.Seq)
		}
	}
}

func TestEngine_Sync_Compaction(t *testing.T) {
	t.Parallel()

	// Each parallel subtest gets its own fixture: the mock driver is not
	// safe for concurrent use.
	t.Run("upsert then delete", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		scope := diff.Scope{UserID: owner}
		id := uuid.NewV7()
		doc := assetDoc(id, owner, uuid.Nil())
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert("asset", doc, stamp(10)),
			remove("asset", doc, stamp(20)),
		}})
		if _, alive := f.assets.Rows()[id]; alive {
			t.Error("row should not exist after compacted upsert+delete")
		}
		if !slices.Contains(f.assets.Tombstones(), id) {
			t.Error("compacted delete should have left a tombstone")
		}
	})

	t.Run("delete then newer upsert", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		scope := diff.Scope{UserID: owner}
		id := uuid.NewV7()
		doc := assetDoc(id, owner, uuid.Nil())
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			remove("asset", doc, stamp(10)),
			upsert("asset", doc, stamp(20)),
		}})
		if _, alive := f.assets.Rows()[id]; !alive {
			t.Error("row should exist: the newer upsert wins compaction")
		}
		if slices.Contains(f.assets.Tombstones(), id) {
			t.Error("compaction should have discarded the losing delete")
		}
	})
}

func TestEngine_Sync_Pagination(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	const total = 10
	want := make(map[uuid.UUID]bool, total)
	var changes []diff.Change
	for i := range total {
		id := uuid.NewV7()
		want[id] = true
		changes = append(changes,
			upsert("asset", assetDoc(id, owner, uuid.Nil()), stamp(uint64(i+1))))
	}
	sync(t, f, scope, &diff.Request{Changes: changes})

	// A second device pages through the backlog with a small limit; the
	// union of pages must contain every document exactly once.
	got := make(map[uuid.UUID]int)
	var since diff.Cursor
	for range 20 {
		res := sync(t, f, scope, &diff.Request{Since: since, Limit: 3})
		for _, p := range res.Patches {
			for _, row := range p.Update {
				var meta struct {
					ID uuid.UUID `json:"id"`
				}
				if err := json.Unmarshal(row.Data, &meta); err != nil {
					t.Fatalf("should not have returned an error: %v", err)
				}
				if row.Time == 0 {
					t.Error("update rows should carry their timestamp")
				}
				got[meta.ID]++
			}
		}
		if res.Next <= since && res.More {
			t.Fatalf("cursor did not advance: got %d after %d",
				res.Next, since)
		}
		since = res.Next
		if !res.More {
			break
		}
	}

	if len(got) != total {
		t.Fatalf("got %d distinct documents; want %d", len(got), total)
	}
	for id, count := range got {
		if !want[id] {
			t.Errorf("got unexpected document %v", id)
		}
		if count != 1 {
			t.Errorf("document %v delivered %d times; want once", id, count)
		}
	}
}

func TestEngine_Sync_Convergence(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	id := uuid.NewV7()

	// Two devices edit the same document concurrently; regardless of
	// arrival order, the highest HLC timestamp must win everywhere.
	editA := upsert("asset", assetDoc(id, owner, uuid.Nil()), stamp(10))
	editB := upsert("asset", jsontext.Value(fmt.Sprintf(
		`{"id":%q,"user_id":%q,"name":"winner"}`, id, owner,
	)), stamp(20))

	orders := [][]diff.Change{
		{editA, editB},
		{editB, editA},
	}

	var results []string
	for _, order := range orders {
		f := setup()
		for _, c := range order {
			sync(t, f, scope, &diff.Request{Changes: []diff.Change{c}})
		}
		results = append(results, string(f.assets.Rows()[id].Data))
	}

	if results[0] != results[1] {
		t.Errorf("interleavings diverged: got %s and %s",
			results[0], results[1])
	}
	var final struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(
		jsontext.Value(results[0]), &final); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if final.Name != "winner" {
		t.Errorf("name: got %q; want %q", final.Name, "winner")
	}
}

func TestEngine_Sync_ChildResolution(t *testing.T) {
	t.Parallel()

	team := uuid.NewV7()

	t.Run("in-batch parent", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		scope := diff.Scope{UserID: owner, Teams: []uuid.UUID{team}}
		assetID, contractID := uuid.NewV7(), uuid.NewV7()

		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			// Child listed first on purpose: resolution must not depend on
			// request order.
			upsert("contract", contractDoc(contractID, assetID), stamp(2)),
			upsert("asset", assetDoc(assetID, owner, team), stamp(1)),
		}})

		if _, alive := f.contracts.Rows()[contractID]; !alive {
			t.Fatal("contract should have been applied")
		}
		metas, err := f.contracts.Resolve(t.Context(), &mock.Tx{},
			[]uuid.UUID{contractID})
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		meta := metas[contractID]
		if meta.UserID != owner {
			t.Errorf("resolved owner: got %v; want %v", meta.UserID, owner)
		}
		if meta.TeamID != team {
			t.Errorf("resolved team: got %v; want %v", meta.TeamID, team)
		}
	})

	t.Run("stored parent", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		scope := diff.Scope{UserID: owner}
		assetID, contractID := uuid.NewV7(), uuid.NewV7()

		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert("asset", assetDoc(assetID, owner, uuid.Nil()), stamp(1)),
		}})
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert("contract", contractDoc(contractID, assetID), stamp(2)),
		}})

		if _, alive := f.contracts.Rows()[contractID]; !alive {
			t.Fatal("contract should have been applied")
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		scope := diff.Scope{UserID: owner}

		c := upsert("contract",
			contractDoc(uuid.NewV7(), uuid.NewV7()), stamp(1))
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})

		rejectedWith(t, err, c.ID, diff.CodeOrphaned)
	})

	t.Run("foreign root", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		outsider := uuid.NewV7()
		assetID := uuid.NewV7()

		sync(t, f, diff.Scope{UserID: owner}, &diff.Request{
			Changes: []diff.Change{
				upsert("asset", assetDoc(assetID, owner, uuid.Nil()), stamp(1)),
			},
		})

		// An outsider references the foreign asset as parent: denied.
		c := upsert("contract", contractDoc(uuid.NewV7(), assetID), stamp(2))
		_, err := f.engine.Sync(t.Context(), diff.Scope{UserID: outsider},
			&diff.Request{Changes: []diff.Change{c}})

		rejectedWith(t, err, c.ID, diff.CodeForbidden)
	})
}

func TestEngine_Sync_Shares(t *testing.T) {
	t.Parallel()

	t.Run("grant touches personal documents", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		team := uuid.NewV7()
		scope := diff.Scope{UserID: owner, Teams: []uuid.UUID{team}}

		share := jsontext.Value(fmt.Sprintf(
			`{"id":%q,"user_id":%q,"team_id":%q}`,
			uuid.NewV7(), owner, team,
		))
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert(diff.ModelShare, share, stamp(1)),
		}})

		if !slices.Contains(f.store.Touched, owner) {
			t.Error("grant should have touched the owner's documents")
		}
	})

	t.Run("foreign share is denied", func(t *testing.T) {
		t.Parallel()
		f := setup()
		owner := uuid.NewV7()
		team := uuid.NewV7()
		// The caller is a member of the team but not the granting owner.
		scope := diff.Scope{
			UserID: uuid.NewV7(),
			Teams:  []uuid.UUID{team},
		}

		share := jsontext.Value(fmt.Sprintf(
			`{"id":%q,"user_id":%q,"team_id":%q}`,
			uuid.NewV7(), owner, team,
		))
		c := upsert(diff.ModelShare, share, stamp(1))
		_, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{c},
		})

		rejectedWith(t, err, c.ID, diff.CodeForbidden)
	})
}

func TestEngine_Sync_LockSet(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	team := uuid.NewV7()
	other := uuid.NewV7() // owner of a foreign doc in a shared team
	scope := diff.Scope{UserID: owner, Teams: []uuid.UUID{team}}

	sync(t, f, scope, &diff.Request{Changes: []diff.Change{
		upsert("asset", assetDoc(uuid.NewV7(), other, team), stamp(1)),
	}})

	if len(f.store.Locked) == 0 {
		t.Fatal("sync should have acquired locks")
	}
	locked := f.store.Locked[len(f.store.Locked)-1]
	for _, key := range []uuid.UUID{owner, team, other} {
		if !slices.Contains(locked, key) {
			t.Errorf("lock set %v should contain %v", locked, key)
		}
	}
}

func TestEngine_Sync_Errors(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	t.Run("too many changes", func(t *testing.T) {
		t.Parallel()
		f := setup(diff.WithMaxChanges(1))
		_, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{
				upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1)),
				upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(2)),
			},
		})
		if !errors.Is(err, diff.ErrTooManyChanges) {
			t.Errorf("got error %v; want ErrTooManyChanges", err)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		f := setup()
		c := upsert("vehicle", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1))
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})

		rejectedWith(t, err, c.ID, diff.CodeUnknownModel)
	})

	t.Run("scope violation", func(t *testing.T) {
		t.Parallel()
		f := setup()
		foreign := uuid.NewV7()
		c := upsert(
			"asset", assetDoc(uuid.NewV7(), foreign, uuid.Nil()), stamp(1),
		)
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})

		rejectedWith(t, err, c.ID, diff.CodeForbidden)
	})

	t.Run("invalid payload", func(t *testing.T) {
		t.Parallel()
		f := setup()
		id := uuid.NewV7()
		doc := jsontext.Value(fmt.Sprintf(
			`{"id":%q,"user_id":%q,"name":""}`, id, owner, // name required
		))
		c := upsert("asset", doc, stamp(1))
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})

		cause := rejectedWith(t, err, c.ID, diff.CodeInvalid)
		if _, found := cause.Fields["name"]; !found {
			t.Errorf("got fields %v; want failure on %q", cause.Fields, "name")
		}
	})

	t.Run("malformed changes", func(t *testing.T) {
		t.Parallel()
		f := setup()

		doc := assetDoc(uuid.NewV7(), owner, uuid.Nil())
		badID := upsert("asset", doc, stamp(1))
		badID.ID = uuid.NewV4() // not a UUIDv7
		badAction := upsert("asset", doc, stamp(2))
		badAction.Action = "replace"
		badData := upsert("asset", nil, stamp(3))
		badTime := upsert("asset", doc, 0)

		_, err := f.engine.Sync(t.Context(), scope, &diff.Request{
			Changes: []diff.Change{badID, badAction, badData, badTime},
		})

		// All four rejections must be reported together, keyed by mutation
		// ID, each naming the offending field.
		for _, tt := range []struct {
			id    uuid.UUID
			field string
		}{
			{badID.ID, "id"},
			{badAction.ID, "action"},
			{badData.ID, "data"},
			{badTime.ID, "time"},
		} {
			cause := rejectedWith(t, err, tt.id, diff.CodeInvalid)
			if _, found := cause.Fields[tt.field]; !found {
				t.Errorf("got fields %v; want failure on %q",
					cause.Fields, tt.field)
			}
		}
	})

	t.Run("clock drift", func(t *testing.T) {
		t.Parallel()
		f := setup()
		future := diff.Stamp(hlc.Pack(uint64(time.Now().Unix())+7200, 0))
		c := upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), future)
		_, err := f.engine.Sync(t.Context(), scope,
			&diff.Request{Changes: []diff.Change{c}})

		rejectedWith(t, err, c.ID, diff.CodeDrift)
	})

	t.Run("resync required", func(t *testing.T) {
		t.Parallel()
		f := setup()
		f.store.SetFloor(100)
		_, err := f.engine.Sync(t.Context(), scope, &diff.Request{Since: 5})

		var rerr *diff.ResyncError
		if !errors.As(err, &rerr) {
			t.Fatalf("got error %v; want ResyncError", err)
		}
		if rerr.Floor != 100 {
			t.Errorf("floor: got %d; want 100", rerr.Floor)
		}
	})
}

func TestEngine_Sync_ApplyOrder(t *testing.T) {
	t.Parallel()

	store := mock.New()
	var log []string
	assets := &recorder{
		Handler: mock.NewHandler(store), name: "asset", log: &log,
	}
	contracts := &recorder{
		Handler: mock.NewHandler(store), name: "contract", log: &log,
	}

	reg := diff.NewRegistry[*mock.Tx]()
	reg.Register[asset]("asset", assets, diff.Root())
	reg.Register[contract]("contract", contracts,
		diff.Owner("asset", "asset_id"))
	engine := diff.New[*mock.Tx](store, reg)

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}
	assetID, contractID := uuid.NewV7(), uuid.NewV7()

	// Push child before parent, and delete parent before child: the engine
	// must reorder both along the dependency graph.
	doc := assetDoc(assetID, owner, uuid.Nil())
	if _, err := engine.Sync(t.Context(), scope, &diff.Request{
		Changes: []diff.Change{
			upsert("contract", contractDoc(contractID, assetID), stamp(2)),
			upsert("asset", doc, stamp(1)),
		},
	}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if _, err := engine.Sync(t.Context(), scope, &diff.Request{
		Changes: []diff.Change{
			remove("asset", doc, stamp(4)),
			remove("contract", contractDoc(contractID, assetID), stamp(3)),
		},
	}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	want := []string{
		"asset:upsert", "contract:upsert", // parents first
		"contract:delete", "asset:delete", // children first
	}
	if !slices.Equal(log, want) {
		t.Errorf("got call order %v; want %v", log, want)
	}
}

func TestEngine_Sync_ZeroChangeKeepsSequence(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	// Seed one document so the sequence has advanced past zero.
	sync(t, f, scope, &diff.Request{Changes: []diff.Change{
		upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1)),
	}})

	before, err := f.store.Watermark(t.Context(), &mock.Tx{})
	if err != nil {
		t.Fatalf("watermark: should not have returned an error: %v", err)
	}

	// A poll that applies zero writes must not consume a barrier: the global
	// sequence stays exactly where it was, yet the poll still delivers the
	// document the device is missing.
	res := sync(t, f, scope, &diff.Request{Since: 0})
	after, err := f.store.Watermark(t.Context(), &mock.Tx{})
	if err != nil {
		t.Fatalf("watermark: should not have returned an error: %v", err)
	}
	if after != before {
		t.Errorf("got sequence %d; want %d (a no-op poll must not advance it)",
			after, before)
	}
	if len(res.Patches) != 1 {
		t.Errorf("got %d patches; want 1 (the missed document)",
			len(res.Patches))
	}

	// A pure replay (all mutation ids already claimed) is likewise a zero-
	// write request and must not advance the sequence either.
	replay := &diff.Request{Changes: []diff.Change{
		upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(2)),
	}}
	sync(t, f, scope, replay)
	seeded, err := f.store.Watermark(t.Context(), &mock.Tx{})
	if err != nil {
		t.Fatalf("watermark: should not have returned an error: %v", err)
	}
	sync(t, f, scope, replay) // identical resend
	replayed, err := f.store.Watermark(t.Context(), &mock.Tx{})
	if err != nil {
		t.Fatalf("watermark: should not have returned an error: %v", err)
	}
	if replayed != seeded {
		t.Errorf("got sequence %d; want %d (a replay must not advance it)",
			replayed, seeded)
	}
}

// countingStore wraps the mock store to count [diff.Store.Grants] calls,
// proving the engine resolves the granted-owner set once per Sync rather
// than once per assemble pass.
type countingStore struct {
	*mock.Store
	grants int
}

func (c *countingStore) Grants(
	ctx context.Context,
	tx *mock.Tx,
	owners []uuid.UUID,
) (map[uuid.UUID][]uuid.UUID, error) {
	c.grants++
	return c.Store.Grants(ctx, tx, owners)
}

func TestEngine_Sync_GrantsResolvedOncePerSync(t *testing.T) {
	t.Parallel()

	inner := mock.New()
	cs := &countingStore{Store: inner}
	assets := mock.NewHandler(inner)

	reg := diff.NewRegistry[*mock.Tx]()
	reg.Register[asset]("asset", assets, diff.Root())
	engine := diff.New[*mock.Tx](cs, reg)

	owner := uuid.NewV7()
	team := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	// The owner has already granted a team access to their personal
	// documents.
	inner.Granted[owner] = []uuid.UUID{team}

	// Writing a personal document folds the granted team into the lock set.
	// assemble runs twice (pre-lock and post-lock verify), but the grant set
	// is resolved only on the pre-lock pass: the verify pass reuses the
	// result, which cannot have changed because the owner is exclusively
	// held.
	if _, err := engine.Sync(t.Context(), scope, &diff.Request{
		Changes: []diff.Change{
			upsert("asset", assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1)),
		},
	}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if cs.grants != 1 {
		t.Errorf("got %d Grants calls; want 1 (verify pass must skip it)",
			cs.grants)
	}

	// The fence is still intact: the granted team was locked exclusively.
	if len(inner.Exclusive) == 0 {
		t.Fatal("sync should have acquired exclusive locks")
	}
	excl := inner.Exclusive[len(inner.Exclusive)-1]
	if !slices.Contains(excl, team) {
		t.Errorf("exclusive lock set %v should contain granted team %v",
			excl, team)
	}
}

func TestNew_Panics(t *testing.T) {
	t.Parallel()

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()
		reg := diff.NewRegistry[*mock.Tx]()
		reg.Register[asset]("asset",
			mock.NewHandler(mock.New()), diff.Root())
		diff.New[*mock.Tx](nil, reg)
	})

	t.Run("empty registry", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()
		diff.New(mock.New(), diff.NewRegistry[*mock.Tx]())
	})
}
