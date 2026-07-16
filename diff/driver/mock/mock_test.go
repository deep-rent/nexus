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

package mock_test

import (
	"encoding/json/jsontext"
	"slices"
	"testing"
	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/diff/driver/mock"
)

func op(
	id uuid.UUID,
	owner string,
	team *string,
	time diff.Stamp,
) diff.Op {
	return diff.Op{
		Meta:   diff.Meta{ID: id, UserID: owner, TeamID: team},
		Action: diff.ActionUpsert,
		Time:   time,
		Data:   jsontext.Value(`{}`),
	}
}

func TestHandler_LWW(t *testing.T) {
	t.Parallel()

	store := mock.New()
	h := mock.NewHandler(store)

	owner := uuid.NewV7().String()
	scope := diff.Scope{UserID: owner}
	id := uuid.NewV7()
	ctx := t.Context()

	if err := h.Upsert(ctx, &mock.Tx{}, scope,
		[]diff.Op{op(id, owner, nil, 100)}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	// A stale upsert must lose against the newer row.
	stale := op(id, owner, nil, 50)
	stale.Data = jsontext.Value(`{"stale":true}`)
	if err := h.Upsert(ctx, &mock.Tx{}, scope,
		[]diff.Op{stale}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got := string(h.Rows()[id].Data); got != `{}` {
		t.Errorf("after stale upsert: got payload %s; want {}", got)
	}

	// A newer delete wins and leaves a tombstone.
	del := op(id, owner, nil, 200)
	del.Action = diff.ActionDelete
	del.Data = nil
	if err := h.Delete(ctx, &mock.Tx{}, scope,
		[]diff.Op{del}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if _, alive := h.Rows()[id]; alive {
		t.Error("row should have been deleted")
	}
	if !slices.Contains(h.Tombstones(), id) {
		t.Error("delete should have left a tombstone")
	}

	// A stale upsert must not resurrect; a newer one must.
	if err := h.Upsert(ctx, &mock.Tx{}, scope,
		[]diff.Op{op(id, owner, nil, 150)}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if _, alive := h.Rows()[id]; alive {
		t.Error("stale upsert should not have resurrected the row")
	}
	if err := h.Upsert(ctx, &mock.Tx{}, scope,
		[]diff.Op{op(id, owner, nil, 300)}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if _, alive := h.Rows()[id]; !alive {
		t.Error("newer upsert should have resurrected the row")
	}
	if slices.Contains(h.Tombstones(), id) {
		t.Error("resurrection should have cleared the tombstone")
	}
}

func TestHandler_HijackGuard(t *testing.T) {
	t.Parallel()

	store := mock.New()
	h := mock.NewHandler(store)

	owner := uuid.NewV7().String()
	attacker := uuid.NewV7().String()
	id := uuid.NewV7()
	ctx := t.Context()

	if err := h.Upsert(ctx, &mock.Tx{}, diff.Scope{UserID: owner},
		[]diff.Op{op(id, owner, nil, 100)}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	// The attacker forges the owner's identity in the payload but syncs
	// under their own scope: the existing row must stay untouched.
	forged := op(id, owner, nil, 200)
	forged.Data = jsontext.Value(`{"hijacked":true}`)
	if err := h.Upsert(ctx, &mock.Tx{}, diff.Scope{UserID: attacker},
		[]diff.Op{forged}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got := string(h.Rows()[id].Data); got != `{}` {
		t.Errorf("after forged upsert: got payload %s; want {}", got)
	}

	del := op(id, owner, nil, 300)
	del.Action = diff.ActionDelete
	del.Data = nil
	if err := h.Delete(ctx, &mock.Tx{}, diff.Scope{UserID: attacker},
		[]diff.Op{del}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if _, alive := h.Rows()[id]; !alive {
		t.Error("row should have survived the foreign delete")
	}
}

func TestHandler_Fetch_Window(t *testing.T) {
	t.Parallel()

	store := mock.New()
	h := mock.NewHandler(store)

	owner := uuid.NewV7().String()
	scope := diff.Scope{UserID: owner}
	ctx := t.Context()

	var ids []uuid.UUID
	for i := range 5 {
		id := uuid.NewV7()
		ids = append(ids, id)
		if err := h.Upsert(ctx, &mock.Tx{}, scope,
			[]diff.Op{op(id, owner, nil, diff.Stamp(100+i))}); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
	}

	got, err := h.Fetch(ctx, &mock.Tx{}, scope, diff.Window{
		Since: 1, // exclusive: skips the first row (seq 1)
		Until: 5, // exclusive: skips the last row (seq 5)
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d versions; want 3", len(got))
	}
	for i, v := range got {
		if v.ID != ids[i+1] {
			t.Errorf("at index %d: got %v; want %v", i, v.ID, ids[i+1])
		}
		if i > 0 && got[i-1].Seq >= v.Seq {
			t.Error("versions should be in ascending sequence order")
		}
	}
}

func TestHandler_Fetch_Grants(t *testing.T) {
	t.Parallel()

	store := mock.New()
	h := mock.NewHandler(store)

	owner := uuid.NewV7().String()
	team := uuid.NewV7().String()
	member := uuid.NewV7().String()
	ctx := t.Context()

	id := uuid.NewV7()
	if err := h.Upsert(ctx, &mock.Tx{}, diff.Scope{UserID: owner},
		[]diff.Op{op(id, owner, nil, 100)}); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	window := diff.Window{Since: 0, Until: 1 << 60, Limit: 10}
	memberScope := diff.Scope{UserID: member, Teams: []string{team}}

	got, err := h.Fetch(ctx, &mock.Tx{}, memberScope, window)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatal("personal document should be invisible before the grant")
	}

	store.Grants[owner] = []string{team}

	got, err = h.Fetch(ctx, &mock.Tx{}, memberScope, window)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if len(got) != 1 {
		t.Fatal("personal document should be visible after the grant")
	}
}
