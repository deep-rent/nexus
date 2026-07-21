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
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/diff"
)

// Caps advertises the optional reference-driver behaviors a [Target]
// implements beyond the documented [diff.Handler] contract. Scenarios that
// depend on a capability are skipped on backends that lack it.
type Caps struct {
	// DepartureTombstones reports whether a team move records a move
	// tombstone for the departed audience (the deletion the old team
	// receives). The postgres reference driver does; the mock driver, which
	// models neither cascades nor departure tombstones, does not.
	DepartureTombstones bool
}

// Target captures everything a scenario needs to drive one backend: the
// shared store, a root handler, a child handler (parented to the root), the
// shares handler, a transaction runner, and seeders for the user and team
// rows a real driver references by foreign key. The type parameter erases the
// backend's transaction handle.
type Target[Tx any] struct {
	// Store is the shared transactional machinery under test.
	Store diff.Store[Tx]
	// Root handles a root document model (id, user_id, team_id in payload).
	Root diff.Handler[Tx]
	// Child handles a model owned by Root; its payload carries the parent
	// reference field named by ChildRef.
	Child diff.Handler[Tx]
	// Shares handles the reserved share model.
	Shares diff.Handler[Tx]
	// ChildRef is the JSON payload field (and, for postgres, column) through
	// which a child references its parent root.
	ChildRef string
	// InTx runs fn inside one committed transaction, failing the test on
	// error.
	InTx func(t *testing.T, fn func(ctx context.Context, tx Tx) error)
	// SeedUser registers a user and returns its id, satisfying the foreign
	// keys of a real driver. It is a no-op allocator on the mock.
	SeedUser func(t *testing.T) uuid.UUID
	// SeedTeam registers a team and returns its id.
	SeedTeam func(t *testing.T) uuid.UUID
	// Caps advertises optional reference-driver behaviors.
	Caps Caps
}

// RunEquivalence runs every shared scenario against the backend produced by
// newTarget. The constructor is invoked once per scenario so backends that
// prefer isolation may return fresh state each time; backends sharing a
// container may return the same handlers with fresh seeders. Scenarios seed
// their own users, teams, and document ids, so a shared store stays isolated.
func RunEquivalence[Tx any](
	t *testing.T,
	newTarget func(t *testing.T) Target[Tx],
) {
	for _, sc := range scenarios[Tx]() {
		t.Run(sc.name, func(t *testing.T) {
			tg := newTarget(t)
			if sc.departure && !tg.Caps.DepartureTombstones {
				t.Skip("backend does not implement departure tombstones")
			}
			sc.run(t, &harness[Tx]{t: t, tg: tg})
		})
	}
}

// scenario is one shared behavior exercised against a backend.
type scenario[Tx any] struct {
	// name identifies the scenario as a subtest.
	name string
	// departure marks scenarios that require the DepartureTombstones
	// capability.
	departure bool
	// run drives the scenario through the harness.
	run func(t *testing.T, h *harness[Tx])
}

// harness wraps a [Target] with the operation runners and fetch-based
// assertions the scenarios share. State is observed exclusively through the
// [diff.Handler] and [diff.Store] interfaces, so both backends are held to
// the same surface.
type harness[Tx any] struct {
	t  *testing.T
	tg Target[Tx]
}

// user registers a fresh user and returns its id.
func (h *harness[Tx]) user() uuid.UUID { return h.tg.SeedUser(h.t) }

// team registers a fresh team and returns its id.
func (h *harness[Tx]) team() uuid.UUID { return h.tg.SeedTeam(h.t) }

// scope builds an authorization scope from a user and its teams.
func scope(user uuid.UUID, teams ...uuid.UUID) diff.Scope {
	return diff.Scope{UserID: user, Teams: teams}
}

// upsert applies the given operations through the handler in one transaction.
func (h *harness[Tx]) upsert(
	hd diff.Handler[Tx],
	s diff.Scope,
	ops ...diff.Op,
) {
	h.t.Helper()
	h.tg.InTx(h.t, func(ctx context.Context, tx Tx) error {
		return hd.Upsert(ctx, tx, s, ops)
	})
}

// remove applies the given delete operations through the handler.
func (h *harness[Tx]) remove(
	hd diff.Handler[Tx],
	s diff.Scope,
	ops ...diff.Op,
) {
	h.t.Helper()
	h.tg.InTx(h.t, func(ctx context.Context, tx Tx) error {
		return hd.Delete(ctx, tx, s, ops)
	})
}

// fetch reads the versions visible to the scope within the window.
func (h *harness[Tx]) fetch(
	hd diff.Handler[Tx],
	s diff.Scope,
	w diff.Window,
) []diff.Version {
	h.t.Helper()
	var out []diff.Version
	h.tg.InTx(h.t, func(ctx context.Context, tx Tx) error {
		var err error
		out, err = hd.Fetch(ctx, tx, s, w)
		return err
	})
	return out
}

// fetchAll reads every version visible to the scope.
func (h *harness[Tx]) fetchAll(
	hd diff.Handler[Tx],
	s diff.Scope,
) []diff.Version {
	return h.fetch(hd, s, diff.Window{Since: 0, Until: 1 << 60, Limit: 1000})
}

// resolve returns the identifying envelope of the given live document.
func (h *harness[Tx]) resolve(
	hd diff.Handler[Tx],
	id uuid.UUID,
) (diff.Meta, bool) {
	h.t.Helper()
	var metas map[uuid.UUID]diff.Meta
	h.tg.InTx(h.t, func(ctx context.Context, tx Tx) error {
		var err error
		metas, err = hd.Resolve(ctx, tx, []uuid.UUID{id})
		return err
	})
	meta, ok := metas[id]
	return meta, ok
}

// read performs a point read through the handler's [diff.Reader]
// implementation, failing the test if the backend does not provide one.
func (h *harness[Tx]) read(
	hd diff.Handler[Tx],
	s diff.Scope,
	id uuid.UUID,
) (diff.Version, bool) {
	h.t.Helper()
	reader, ok := hd.(diff.Reader[Tx])
	if !ok {
		h.t.Fatalf("handler %T does not implement diff.Reader", hd)
	}
	var out diff.Version
	var found bool
	h.tg.InTx(h.t, func(ctx context.Context, tx Tx) error {
		var err error
		out, found, err = reader.Read(ctx, tx, s, id)
		return err
	})
	return out, found
}

// find returns the single version of id visible to the scope, if any.
func (h *harness[Tx]) find(
	hd diff.Handler[Tx],
	s diff.Scope,
	id uuid.UUID,
) (diff.Version, bool) {
	h.t.Helper()
	for _, v := range h.fetchAll(hd, s) {
		if v.ID == id {
			return v, true
		}
	}
	return diff.Version{}, false
}

// wantLive asserts that id is live to the scope with the given timestamp and
// payload marker, and returns the version.
func (h *harness[Tx]) wantLive(
	hd diff.Handler[Tx],
	s diff.Scope,
	id uuid.UUID,
	time diff.Stamp,
	mark int,
) diff.Version {
	h.t.Helper()
	v, ok := h.find(hd, s, id)
	if !ok {
		h.t.Fatalf("id %v: got absent; want live", id)
	}
	if v.Deleted {
		h.t.Fatalf("id %v: got tombstone; want live", id)
	}
	if v.Time != time {
		h.t.Errorf("id %v: got time %d; want %d", id, v.Time, time)
	}
	if got := marker(h.t, v.Data); got != mark {
		h.t.Errorf("id %v: got marker %d; want %d", id, got, mark)
	}
	return v
}

// wantDead asserts that id is a tombstone to the scope with the given
// timestamp, and returns the version.
func (h *harness[Tx]) wantDead(
	hd diff.Handler[Tx],
	s diff.Scope,
	id uuid.UUID,
	time diff.Stamp,
) diff.Version {
	h.t.Helper()
	v, ok := h.find(hd, s, id)
	if !ok {
		h.t.Fatalf("id %v: got absent; want tombstone", id)
	}
	if !v.Deleted {
		h.t.Fatalf("id %v: got live; want tombstone", id)
	}
	if v.Time != time {
		h.t.Errorf("id %v: got tombstone time %d; want %d", id, v.Time, time)
	}
	if len(v.Data) != 0 {
		h.t.Errorf("id %v: got tombstone payload %s; want none", id, v.Data)
	}
	return v
}

// wantAbsent asserts that id is neither live nor tombstoned to the scope.
func (h *harness[Tx]) wantAbsent(
	hd diff.Handler[Tx],
	s diff.Scope,
	id uuid.UUID,
) {
	h.t.Helper()
	if v, ok := h.find(hd, s, id); ok {
		h.t.Errorf(
			"id %v: got version (deleted %t); want absent",
			id,
			v.Deleted,
		)
	}
}

// upsertOp builds a root or child upsert operation with a payload carrying
// the given marker.
func upsertOp(
	id uuid.UUID,
	owner uuid.UUID,
	team uuid.UUID,
	time diff.Stamp,
	data string,
) diff.Op {
	return diff.Op{
		Meta:   diff.Meta{ID: id, UserID: owner, TeamID: team},
		Action: diff.ActionUpsert,
		Time:   time,
		Data:   jsontext.Value(data),
	}
}

// deleteOp builds a delete operation.
func deleteOp(
	id uuid.UUID,
	owner uuid.UUID,
	team uuid.UUID,
	time diff.Stamp,
) diff.Op {
	return diff.Op{
		Meta:   diff.Meta{ID: id, UserID: owner, TeamID: team},
		Action: diff.ActionDelete,
		Time:   time,
	}
}

// doc renders a root payload carrying an integer marker used to prove which
// write won a conflict.
func doc(id uuid.UUID, mark int) string {
	return fmt.Sprintf(`{"id":%q,"v":%d}`, id.String(), mark)
}

// childDoc renders a child payload carrying the parent reference under ref
// plus an integer marker.
func childDoc(id, parent uuid.UUID, ref string, mark int) string {
	return fmt.Sprintf(`{"id":%q,%q:%q,"v":%d}`,
		id.String(), ref, parent.String(), mark)
}

// marker extracts the integer payload marker, failing the test on malformed
// data. Backends normalize JSON differently (the postgres jsonb round-trip
// reorders keys and reformats whitespace), so scenarios compare this parsed
// field rather than the raw bytes.
func marker(t *testing.T, data jsontext.Value) int {
	t.Helper()
	var m struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf(
			"unmarshal payload: should not have returned an error: %v",
			err,
		)
	}
	return m.V
}
