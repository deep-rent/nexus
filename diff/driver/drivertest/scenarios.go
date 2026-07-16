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

package drivertest

import (
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/diff"
)

// scenarios returns the shared behavior suite. Adding an entry covers both
// backends at once. Every assertion observes state through Fetch and Resolve,
// and compares HLC timestamps (deterministic) rather than sequence values
// (monotonic but backend-specific).
func scenarios[Tx any]() []scenario[Tx] {
	return []scenario[Tx]{
		{name: "lww", run: scLWW[Tx]},
		{name: "tombstone_lifecycle", run: scTombstone[Tx]},
		{name: "hijack_guard", run: scHijack[Tx]},
		{name: "owner_immutable", run: scOwnerImmutable[Tx]},
		{name: "fetch_window", run: scFetchWindow[Tx]},
		{name: "grant_visibility", run: scGrantVisibility[Tx]},
		{name: "child_lww", run: scChild[Tx]},
		{name: "team_move_departure", departure: true, run: scDeparture[Tx]},
	}
}

// scLWW covers row-level last-write-wins: a newer upsert wins, an older one
// is skipped, and an equal-timestamp upsert keeps the existing row.
func scLWW[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	s := scope(owner)
	id := uuid.NewV7()

	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 100, doc(id, 1)))
	h.wantLive(h.tg.Root, s, id, 100, 1)

	// A stale upsert loses: the row keeps its timestamp and payload.
	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 50, doc(id, 9)))
	h.wantLive(h.tg.Root, s, id, 100, 1)

	// An equal-timestamp upsert keeps the existing row.
	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 100, doc(id, 9)))
	h.wantLive(h.tg.Root, s, id, 100, 1)

	// A strictly newer upsert wins.
	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 200, doc(id, 2)))
	h.wantLive(h.tg.Root, s, id, 200, 2)
}

// scTombstone covers the tombstone lifecycle: a delete leaves a tombstone, a
// stale delete is a no-op, a stale upsert cannot resurrect, a newer upsert
// resurrects and clears the tombstone, and a delete of an absent document
// tombstones the payload identity.
func scTombstone[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	s := scope(owner)
	id := uuid.NewV7()

	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 100, doc(id, 1)))

	// A newer delete wins and leaves a tombstone carrying its timestamp.
	h.remove(h.tg.Root, s, deleteOp(id, owner, nil, 200))
	h.wantDead(h.tg.Root, s, id, 200)

	// A stale delete of the tombstoned document is a no-op.
	h.remove(h.tg.Root, s, deleteOp(id, owner, nil, 150))
	h.wantDead(h.tg.Root, s, id, 200)

	// A stale upsert cannot resurrect.
	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 150, doc(id, 9)))
	h.wantDead(h.tg.Root, s, id, 200)

	// A newer upsert resurrects the document and clears the tombstone.
	h.upsert(h.tg.Root, s, upsertOp(id, owner, nil, 300, doc(id, 5)))
	h.wantLive(h.tg.Root, s, id, 300, 5)

	// Deleting an absent document tombstones the payload identity.
	absent := uuid.NewV7()
	h.remove(h.tg.Root, s, deleteOp(absent, owner, nil, 40))
	h.wantDead(h.tg.Root, s, absent, 40)
	if meta, ok := h.resolve(h.tg.Root, absent); ok {
		t.Errorf("id %v: got resolved live %v; want absent", absent, meta)
	}
}

// scHijack covers the hijack guard: an out-of-scope caller cannot overwrite
// or delete an existing row, even with a newer timestamp and a forged payload
// identity.
func scHijack[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	attacker := h.user()
	id := uuid.NewV7()

	h.upsert(h.tg.Root, scope(owner), upsertOp(id, owner, nil, 100, doc(id, 1)))

	// A forged upsert under the attacker's scope leaves the row untouched.
	h.upsert(h.tg.Root, scope(attacker), upsertOp(id, owner, nil, 200, doc(id, 9)))
	h.wantLive(h.tg.Root, scope(owner), id, 100, 1)

	// A foreign delete cannot remove the row nor tombstone it.
	h.remove(h.tg.Root, scope(attacker), deleteOp(id, owner, nil, 300))
	h.wantLive(h.tg.Root, scope(owner), id, 100, 1)
}

// scOwnerImmutable covers owner immutability: a team member may update a team
// document, but the owner never yields to the payload identity.
func scOwnerImmutable[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	member := h.user()
	team := h.team()
	id := uuid.NewV7()

	h.upsert(h.tg.Root, scope(owner, team),
		upsertOp(id, owner, &team, 100, doc(id, 1)))

	// The member's update applies, but the forged owner is ignored.
	h.upsert(h.tg.Root, scope(member, team),
		upsertOp(id, member, &team, 200, doc(id, 2)))
	h.wantLive(h.tg.Root, scope(owner, team), id, 200, 2)

	meta, ok := h.resolve(h.tg.Root, id)
	if !ok {
		t.Fatalf("id %v: should have resolved", id)
	}
	if meta.UserID != owner {
		t.Errorf("got owner %q; want %q (immutable)", meta.UserID, owner)
	}
}

// scFetchWindow covers the feed scan: exclusive sequence bounds, ascending
// order, the limit cap, interleaved tombstones, and populated timestamps on
// both live and tombstone rows. It asserts on order and set membership, never
// on absolute sequence values, which differ between backends.
func scFetchWindow[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	s := scope(owner)

	ids := make([]uuid.UUID, 5)
	for i := range ids {
		ids[i] = uuid.NewV7()
		h.upsert(h.tg.Root, s,
			upsertOp(ids[i], owner, nil, diff.Stamp(100+i), doc(ids[i], i)))
	}

	// The full scan returns all five rows in ascending sequence order with
	// their HLC timestamps intact.
	all := h.fetchAll(h.tg.Root, s)
	if got, want := len(all), 5; got != want {
		t.Fatalf("full scan: got %d versions; want %d", got, want)
	}
	for i, v := range all {
		if v.ID != ids[i] {
			t.Errorf("full scan at %d: got id %v; want %v", i, v.ID, ids[i])
		}
		if want := diff.Stamp(100 + i); v.Time != want {
			t.Errorf("full scan at %d: got time %d; want %d", i, v.Time, want)
		}
		if i > 0 && all[i-1].Seq >= v.Seq {
			t.Errorf("full scan at %d: seq %d not after %d",
				i, v.Seq, all[i-1].Seq)
		}
	}

	// Both window bounds are exclusive: bounding by the first and last
	// observed sequence values drops both ends.
	mid := h.fetch(h.tg.Root, s, diff.Window{
		Since: all[0].Seq,
		Until: all[4].Seq,
		Limit: 1000,
	})
	if got := versionIDs(mid); !equal(got, ids[1:4]) {
		t.Errorf("bounded scan: got ids %v; want %v", got, ids[1:4])
	}

	// The limit caps the page to the lowest sequence values.
	limited := h.fetch(h.tg.Root, s, diff.Window{Since: 0, Until: 1 << 60, Limit: 2})
	if got := versionIDs(limited); !equal(got, ids[:2]) {
		t.Errorf("limited scan: got ids %v; want %v", got, ids[:2])
	}

	// A tombstone interleaves at the end and carries its own timestamp.
	gone := uuid.NewV7()
	h.remove(h.tg.Root, s, deleteOp(gone, owner, nil, 200))
	all = h.fetchAll(h.tg.Root, s)
	if got, want := len(all), 6; got != want {
		t.Fatalf("after delete: got %d versions; want %d", got, want)
	}
	last := all[len(all)-1]
	if last.ID != gone || !last.Deleted || last.Time != 200 {
		t.Errorf("got last version %v (deleted %t, time %d);"+
			" want tombstone %v at time 200",
			last.ID, last.Deleted, last.Time, gone)
	}
}

// scGrantVisibility covers grant-based visibility: a personal document is
// invisible to a team until a share grants it, visible after, and hidden
// again once the share is deleted.
func scGrantVisibility[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	team := h.team()
	member := h.user()

	ownerScope := scope(owner)
	memberScope := scope(member, team)

	id := uuid.NewV7()
	h.upsert(h.tg.Root, ownerScope, upsertOp(id, owner, nil, 100, doc(id, 1)))

	// Before the grant, the personal document is invisible to the team.
	h.wantAbsent(h.tg.Root, memberScope, id)

	// The grant exposes the owner's personal document to the team.
	grant := uuid.NewV7()
	h.upsert(h.tg.Shares, ownerScope, upsertOp(grant, owner, &team, 110, "{}"))
	h.wantLive(h.tg.Root, memberScope, id, 100, 1)

	// Revoking the grant hides the document again.
	h.remove(h.tg.Shares, ownerScope, deleteOp(grant, owner, &team, 120))
	h.wantAbsent(h.tg.Root, memberScope, id)
}

// scChild exercises the child handler and its parent linkage: a child model
// honors the same last-write-wins and fetch semantics as a root, and resolves
// to the denormalized owner identity carried on its operations.
func scChild[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	s := scope(owner)
	parent := uuid.NewV7()
	id := uuid.NewV7()

	h.upsert(h.tg.Child, s,
		upsertOp(id, owner, nil, 100, childDoc(id, parent, h.tg.ChildRef, 1)))
	h.wantLive(h.tg.Child, s, id, 100, 1)

	// A newer upsert wins on the child, exactly as on the root.
	h.upsert(h.tg.Child, s,
		upsertOp(id, owner, nil, 200, childDoc(id, parent, h.tg.ChildRef, 2)))
	h.wantLive(h.tg.Child, s, id, 200, 2)

	meta, ok := h.resolve(h.tg.Child, id)
	if !ok {
		t.Fatalf("id %v: child should have resolved", id)
	}
	if meta.UserID != owner {
		t.Errorf("got child owner %q; want %q", meta.UserID, owner)
	}
}

// scDeparture covers the team-move departure tombstone: moving a root's team
// leaves the old team a deletion for that id, while the live row survives
// under the new team. Only backends advertising DepartureTombstones run this.
func scDeparture[Tx any](t *testing.T, h *harness[Tx]) {
	owner := h.user()
	teamA := h.team()
	teamB := h.team()
	writer := scope(owner, teamA, teamB)

	// Strangers observing each team's feed (reads need no seeded user).
	oldAudience := scope(uuid.NewV7().String(), teamA)
	newAudience := scope(uuid.NewV7().String(), teamB)

	id := uuid.NewV7()
	h.upsert(h.tg.Root, writer, upsertOp(id, owner, &teamA, 100, doc(id, 1)))
	h.wantLive(h.tg.Root, oldAudience, id, 100, 1)

	// Moving the root to team B leaves team A a move tombstone at the move's
	// timestamp, while team B and the owner see the live row.
	h.upsert(h.tg.Root, writer, upsertOp(id, owner, &teamB, 200, doc(id, 2)))
	h.wantDead(h.tg.Root, oldAudience, id, 200)
	h.wantLive(h.tg.Root, newAudience, id, 200, 2)
	h.wantLive(h.tg.Root, scope(owner), id, 200, 2)
}

// versionIDs projects versions onto their document ids, preserving order.
func versionIDs(vs []diff.Version) []uuid.UUID {
	out := make([]uuid.UUID, len(vs))
	for i, v := range vs {
		out[i] = v.ID
	}
	return out
}

// equal reports whether two id slices match element for element.
func equal(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
