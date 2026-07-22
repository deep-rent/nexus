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
	"encoding/json/v2"
	"slices"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/dat/diff"
)

// replica applies patch feeds the way a client does, so a paginated feed can
// be checked against the server's authoritative state.
type replica struct {
	docs map[uuid.UUID][]byte
}

func newReplica() *replica {
	return &replica{docs: make(map[uuid.UUID][]byte)}
}

// apply folds one response page into the replica: updates in patch order,
// then deletes in reverse patch order, as the client contract requires.
func (r *replica) apply(t *testing.T, resp *diff.Response) {
	t.Helper()
	for _, p := range resp.Patches {
		for _, row := range p.Update {
			var m struct {
				ID uuid.UUID `json:"id"`
			}
			if err := json.Unmarshal(row.Data, &m); err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			r.docs[m.ID] = row.Data
		}
	}
	for _, v := range slices.Backward(resp.Patches) {
		for _, d := range v.Delete {
			delete(r.docs, d.ID)
		}
	}
}

// drain paginates from cursor zero until the feed is exhausted, applying
// every page, and returns the number of pages consumed.
func (r *replica) drain(
	t *testing.T,
	f *fixture,
	scope diff.Scope,
	limit int,
) int {
	t.Helper()
	var since diff.Cursor
	pages := 0
	for {
		resp := sync(t, f, scope, &diff.Request{Since: since, Limit: limit})
		r.apply(t, resp)
		pages++
		if since != 0 && resp.Next < since {
			t.Fatalf("cursor regressed: %d then %d", since, resp.Next)
		}
		since = resp.Next
		if !resp.More {
			return pages
		}
		if pages > 1000 {
			t.Fatal("pagination did not terminate")
		}
	}
}

// TestProperty_Pagination_NoSkipWithTombstones seeds a mix of live documents
// and tombstones, then verifies that a fresh device paginating with a small
// limit reconstructs exactly the server's live set: every live document
// delivered, every deleted document absent, none skipped or duplicated.
func TestProperty_Pagination_NoSkipWithTombstones(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	const n = 40
	live := make(map[uuid.UUID]struct{})
	var tick uint64
	for i := range n {
		id := uuid.NewV7()
		tick++
		doc := assetDoc(id, owner, uuid.Nil())
		sync(t, f, scope, &diff.Request{Changes: []diff.Change{
			upsert("asset", doc, stamp(tick)),
		}})
		if i%3 == 0 {
			tick++
			sync(t, f, scope, &diff.Request{Changes: []diff.Change{
				remove("asset", doc, stamp(tick)),
			}})
		} else {
			live[id] = struct{}{}
		}
	}

	rep := newReplica()
	pages := rep.drain(t, f, scope, 4)
	if pages < 2 {
		t.Fatalf("expected multiple pages; got %d", pages)
	}

	if len(rep.docs) != len(live) {
		t.Fatalf("replica has %d docs; want %d live", len(rep.docs), len(live))
	}
	for id := range live {
		if _, ok := rep.docs[id]; !ok {
			t.Errorf("live document %v missing from replica", id)
		}
	}
}

// TestProperty_Convergence_WithDeletes checks that concurrent upsert and
// delete operations on the same documents, applied in different arrival
// orders, converge to identical final server state.
func TestProperty_Convergence_WithDeletes(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	scope := diff.Scope{UserID: owner}

	idA, idB := uuid.NewV7(), uuid.NewV7()
	docA := assetDoc(idA, owner, uuid.Nil())
	docB := assetDoc(idB, owner, uuid.Nil())

	upsA := upsert("asset", docA, stamp(30)) // A: upsert wins (later)
	delA := remove("asset", docA, stamp(10))
	upsB := upsert("asset", docB, stamp(10))
	delB := remove("asset", docB, stamp(30)) // B: delete wins (later)

	orders := [][]diff.Change{
		{upsA, delA, upsB, delB},
		{delB, upsB, delA, upsA},
		{delA, delB, upsA, upsB},
		{upsB, upsA, delB, delA},
	}

	type state struct{ aLive, bLive bool }
	var results []state
	for _, order := range orders {
		f := setup()
		for _, c := range order {
			sync(t, f, scope, &diff.Request{Changes: []diff.Change{c}})
		}
		_, aLive := f.assets.Rows()[idA]
		_, bLive := f.assets.Rows()[idB]
		results = append(results, state{aLive, bLive})
	}

	want := results[0]
	if !want.aLive || want.bLive {
		t.Errorf("converged to %+v; want {aLive:true bLive:false}", want)
	}
	for i, got := range results {
		if got != want {
			t.Errorf("order %d converged to %+v; want %+v", i, got, want)
		}
	}
}
