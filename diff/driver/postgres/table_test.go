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

package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/diff/driver/postgres"
)

// setupTables provisions a store plus a three-level entity hierarchy:
// assets (root) <- files <- notes.
func setupTables(t *testing.T) (
	*sql.DB,
	*postgres.Store,
	*postgres.Table, // assets
	*postgres.Table, // files
	*postgres.Table, // notes
) {
	t.Helper()

	db, s := setupStore(t)
	ctx := context.Background()

	stmts := []string{
		`CREATE TABLE assets (
		  id      UUID PRIMARY KEY,
		  user_id UUID NOT NULL,
		  team_id UUID,
		  hlc     BIGINT NOT NULL,
		  seq     BIGINT NOT NULL,
		  data    JSONB NOT NULL
		)`,
		`CREATE TABLE files (
		  id           UUID PRIMARY KEY,
		  root_user_id UUID NOT NULL,
		  root_team_id UUID,
		  asset_id     UUID NOT NULL,
		  hlc          BIGINT NOT NULL,
		  seq          BIGINT NOT NULL,
		  data         JSONB NOT NULL
		)`,
		`CREATE TABLE notes (
		  id           UUID PRIMARY KEY,
		  root_user_id UUID NOT NULL,
		  root_team_id UUID,
		  file_id      UUID NOT NULL,
		  hlc          BIGINT NOT NULL,
		  seq          BIGINT NOT NULL,
		  data         JSONB NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create table: should not have returned an error: %v", err)
		}
	}

	assets := postgres.NewTable(s, "asset", "assets")
	files := postgres.NewTable(s, "file", "files",
		postgres.WithParent("assets", "asset_id"))
	notes := postgres.NewTable(s, "note", "notes",
		postgres.WithParent("files", "file_id"))

	return db, s, assets, files, notes
}

func scopeOf(user string, teams ...string) diff.Scope {
	return diff.Scope{UserID: user, Teams: teams}
}

func upsertOp(
	id uuid.UUID,
	user string,
	team *string,
	ts uint64,
	data string,
) diff.Op {
	return diff.Op{
		Meta:   diff.Meta{ID: id, UserID: user, TeamID: team},
		Action: diff.ActionUpsert,
		Time:   diff.Stamp(ts),
		Data:   jsontext.Value(data),
	}
}

func deleteOp(id uuid.UUID, user string, team *string, ts uint64) diff.Op {
	return diff.Op{
		Meta:   diff.Meta{ID: id, UserID: user, TeamID: team},
		Action: diff.ActionDelete,
		Time:   diff.Stamp(ts),
	}
}

func assetDoc(id uuid.UUID, v int) string {
	return fmt.Sprintf(`{"id":%q,"v":%d}`, id.String(), v)
}

func fileDoc(id, asset uuid.UUID) string {
	return fmt.Sprintf(`{"id":%q,"asset_id":%q}`, id.String(), asset.String())
}

func noteDoc(id, file uuid.UUID) string {
	return fmt.Sprintf(`{"id":%q,"file_id":%q}`, id.String(), file.String())
}

func applyUpserts(
	t *testing.T,
	s *postgres.Store,
	h diff.Handler[*sql.Tx],
	scope diff.Scope,
	ops ...diff.Op,
) {
	t.Helper()
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		return h.Upsert(ctx, tx, scope, ops)
	})
}

func applyDeletes(
	t *testing.T,
	s *postgres.Store,
	h diff.Handler[*sql.Tx],
	scope diff.Scope,
	ops ...diff.Op,
) {
	t.Helper()
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		return h.Delete(ctx, tx, scope, ops)
	})
}

func fetchAll(
	t *testing.T,
	s *postgres.Store,
	h diff.Handler[*sql.Tx],
	scope diff.Scope,
) []diff.Version {
	t.Helper()
	var out []diff.Version
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		out, err = h.Fetch(ctx, tx, scope, diff.Window{
			Since: 0,
			Until: 1 << 60,
			Limit: 1000,
		})
		return err
	})
	return out
}

// rowInt scans a single int64 column, reporting whether the row exists.
func rowInt(
	t *testing.T,
	db *sql.DB,
	query string,
	args ...any,
) (int64, bool) {
	t.Helper()
	var v int64
	err := db.QueryRow(query, args...).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("query: should not have returned an error: %v", err)
	}
	return v, true
}

// rowStr scans a single textual column, reporting whether the row exists.
func rowStr(
	t *testing.T,
	db *sql.DB,
	query string,
	args ...any,
) (sql.NullString, bool) {
	t.Helper()
	var v sql.NullString
	err := db.QueryRow(query, args...).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false
	}
	if err != nil {
		t.Fatalf("query: should not have returned an error: %v", err)
	}
	return v, true
}

// tombstoneHLC returns the tombstone timestamp of the given document, if
// one exists.
func tombstoneHLC(
	t *testing.T,
	db *sql.DB,
	typ string,
	id uuid.UUID,
) (int64, bool) {
	t.Helper()
	return rowInt(t, db,
		"SELECT hlc FROM diff_tombstones WHERE type = $1 AND id = $2::uuid",
		typ, id.String(),
	)
}

func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: should have panicked", name)
		}
	}()
	fn()
}

func TestNewTable_Panics(t *testing.T) {
	// No live database connection is needed to exercise registration.
	db, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("open: should not have returned an error: %v", err)
	}
	s := postgres.New(db)

	expectPanic(t, "nil store", func() {
		postgres.NewTable(nil, "asset", "assets")
	})
	expectPanic(t, "empty type", func() {
		postgres.NewTable(s, "", "assets")
	})
	expectPanic(t, "empty table", func() {
		postgres.NewTable(s, "asset", "")
	})
	expectPanic(t, "unknown parent", func() {
		postgres.NewTable(s, "file", "files",
			postgres.WithParent("missing", "asset_id"))
	})

	postgres.NewTable(s, "asset", "assets")
	expectPanic(t, "duplicate table", func() {
		postgres.NewTable(s, "asset2", "assets")
	})
}

func TestTable_RootLWW(t *testing.T) {
	db, s, assets, _, _ := setupTables(t)

	owner := uuid.NewV7().String()
	scope := scopeOf(owner)
	x := uuid.NewV7()

	// Initial insert.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 10, assetDoc(x, 1)))
	if hlc, ok := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); !ok || hlc != 10 {
		t.Fatalf("after insert: got hlc %d, exists %t; want 10, true", hlc, ok)
	}

	// Newer wins.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 20, assetDoc(x, 2)))
	if v, _ := rowStr(t, db,
		"SELECT data ->> 'v' FROM assets WHERE id = $1::uuid", x.String(),
	); v.String != "2" {
		t.Errorf("after newer upsert: got v %q; want %q", v.String, "2")
	}

	// Older is skipped.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 15, assetDoc(x, 9)))
	if v, _ := rowStr(t, db,
		"SELECT data ->> 'v' FROM assets WHERE id = $1::uuid", x.String(),
	); v.String != "2" {
		t.Errorf("after stale upsert: got v %q; want %q", v.String, "2")
	}

	// Equal timestamps keep the existing row.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 20, assetDoc(x, 9)))
	if v, _ := rowStr(t, db,
		"SELECT data ->> 'v' FROM assets WHERE id = $1::uuid", x.String(),
	); v.String != "2" {
		t.Errorf("after equal upsert: got v %q; want %q", v.String, "2")
	}

	// Delete removes the row and records a tombstone.
	applyDeletes(t, s, assets, scope, deleteOp(x, owner, nil, 25))
	if _, ok := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); ok {
		t.Error("after delete: row should be gone")
	}
	if hlc, ok := tombstoneHLC(t, db, "asset", x); !ok || hlc != 25 {
		t.Errorf("after delete: got tombstone hlc %d, exists %t; want 25, true",
			hlc, ok)
	}

	// The tombstone blocks stale upserts.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 22, assetDoc(x, 3)))
	if _, ok := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); ok {
		t.Error("after blocked upsert: row should not resurrect")
	}
	if hlc, _ := tombstoneHLC(t, db, "asset", x); hlc != 25 {
		t.Errorf("after blocked upsert: got tombstone hlc %d; want 25", hlc)
	}

	// A newer upsert resurrects the document and clears the tombstone.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 30, assetDoc(x, 4)))
	if hlc, ok := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); !ok || hlc != 30 {
		t.Errorf("after resurrect: got hlc %d, exists %t; want 30, true", hlc, ok)
	}
	if _, ok := tombstoneHLC(t, db, "asset", x); ok {
		t.Error("after resurrect: tombstone should be cleared")
	}

	// Deleting an absent document tombstones the payload identity.
	y := uuid.NewV7()
	applyDeletes(t, s, assets, scope, deleteOp(y, owner, nil, 5))
	if hlc, ok := tombstoneHLC(t, db, "asset", y); !ok || hlc != 5 {
		t.Errorf("absent delete: got tombstone hlc %d, exists %t; want 5, true",
			hlc, ok)
	}
	if user, _ := rowStr(t, db,
		"SELECT user_id::text FROM diff_tombstones"+
			" WHERE type = 'asset' AND id = $1::uuid", y.String(),
	); user.String != owner {
		t.Errorf("absent delete: got tombstone user %q; want %q",
			user.String, owner)
	}

	// A stale delete is a complete no-op: the row survives and no
	// tombstone appears.
	applyDeletes(t, s, assets, scope, deleteOp(x, owner, nil, 10))
	if hlc, ok := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); !ok || hlc != 30 {
		t.Errorf("after stale delete: got hlc %d, exists %t; want 30, true",
			hlc, ok)
	}
	if _, ok := tombstoneHLC(t, db, "asset", x); ok {
		t.Error("after stale delete: no tombstone should exist")
	}
}

func TestTable_HijackGuard(t *testing.T) {
	db, s, assets, _, _ := setupTables(t)

	owner := uuid.NewV7().String()
	attacker := uuid.NewV7().String()
	x := uuid.NewV7()

	applyUpserts(t, s, assets, scopeOf(owner),
		upsertOp(x, owner, nil, 10, assetDoc(x, 1)))

	// An out-of-scope caller cannot overwrite the row, even with a newer
	// timestamp and a forged payload identity.
	applyUpserts(t, s, assets, scopeOf(attacker),
		upsertOp(x, attacker, nil, 99, assetDoc(x, 666)))
	if user, _ := rowStr(t, db,
		"SELECT user_id::text FROM assets WHERE id = $1::uuid", x.String(),
	); user.String != owner {
		t.Errorf("got owner %q; want %q", user.String, owner)
	}
	if hlc, _ := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); hlc != 10 {
		t.Errorf("got hlc %d; want 10 (untouched)", hlc)
	}

	// Nor can they delete it: the row survives and no tombstone appears.
	applyDeletes(t, s, assets, scopeOf(attacker),
		deleteOp(x, attacker, nil, 99))
	if _, ok := rowInt(t, db,
		"SELECT hlc FROM assets WHERE id = $1::uuid", x.String(),
	); !ok {
		t.Error("row should have survived the foreign delete")
	}
	if _, ok := tombstoneHLC(t, db, "asset", x); ok {
		t.Error("no tombstone should exist after the foreign delete")
	}
}

func TestTable_OwnerImmutable(t *testing.T) {
	db, s, assets, _, _ := setupTables(t)

	owner := uuid.NewV7().String()
	member := uuid.NewV7().String()
	team := uuid.NewV7().String()
	x := uuid.NewV7()

	applyUpserts(t, s, assets, scopeOf(owner, team),
		upsertOp(x, owner, &team, 10, assetDoc(x, 1)))

	// A team member may update the document, but the owner column never
	// yields to the payload identity.
	applyUpserts(t, s, assets, scopeOf(member, team),
		upsertOp(x, member, &team, 20, assetDoc(x, 2)))

	if v, _ := rowStr(t, db,
		"SELECT data ->> 'v' FROM assets WHERE id = $1::uuid", x.String(),
	); v.String != "2" {
		t.Errorf("got v %q; want %q (update applied)", v.String, "2")
	}
	if user, _ := rowStr(t, db,
		"SELECT user_id::text FROM assets WHERE id = $1::uuid", x.String(),
	); user.String != owner {
		t.Errorf("got owner %q; want %q (immutable)", user.String, owner)
	}
}

func TestTable_Resolve(t *testing.T) {
	_, s, assets, files, _ := setupTables(t)

	owner := uuid.NewV7().String()
	team := uuid.NewV7().String()
	scope := scopeOf(owner, team)
	x := uuid.NewV7()
	f := uuid.NewV7()

	applyUpserts(t, s, assets, scope,
		upsertOp(x, owner, &team, 10, assetDoc(x, 1)))
	applyUpserts(t, s, files, scope,
		upsertOp(f, owner, &team, 10, fileDoc(f, x)))

	missing := uuid.NewV7()
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		metas, err := assets.Resolve(ctx, tx, []uuid.UUID{x, missing})
		if err != nil {
			return err
		}
		if got, want := len(metas), 1; got != want {
			t.Fatalf("got %d envelopes; want %d", got, want)
		}
		meta := metas[x]
		if meta.UserID != owner {
			t.Errorf("got owner %v; want %v", meta.UserID, owner)
		}
		if meta.TeamID == nil || *meta.TeamID != team {
			t.Errorf("got team %v; want %v", meta.TeamID, team)
		}

		// Child envelopes carry the denormalized root identity.
		metas, err = files.Resolve(ctx, tx, []uuid.UUID{f})
		if err != nil {
			return err
		}
		meta, ok := metas[f]
		if !ok {
			t.Fatal("child document should have resolved")
		}
		if meta.UserID != owner {
			t.Errorf("got child owner %v; want %v", meta.UserID, owner)
		}
		if meta.TeamID == nil || *meta.TeamID != team {
			t.Errorf("got child team %v; want %v", meta.TeamID, team)
		}
		return nil
	})
}

func TestTable_TeamMoveCascade(t *testing.T) {
	db, s, assets, files, notes := setupTables(t)

	owner := uuid.NewV7().String()
	team := uuid.NewV7().String()
	scope := scopeOf(owner, team)

	x := uuid.NewV7()
	f := uuid.NewV7()
	n := uuid.NewV7()

	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 10, assetDoc(x, 1)))
	applyUpserts(t, s, files, scope, upsertOp(f, owner, nil, 10, fileDoc(f, x)))
	applyUpserts(t, s, notes, scope, upsertOp(n, owner, nil, 10, noteDoc(n, f)))

	seqF0, _ := rowInt(t, db,
		"SELECT seq FROM files WHERE id = $1::uuid", f.String())
	seqN0, _ := rowInt(t, db,
		"SELECT seq FROM notes WHERE id = $1::uuid", n.String())

	// Moving the root into a team updates all descendants.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, &team, 20, assetDoc(x, 2)))

	if got, _ := rowStr(t, db,
		"SELECT team_id::text FROM assets WHERE id = $1::uuid", x.String(),
	); got.String != team {
		t.Errorf("got root team %q; want %q", got.String, team)
	}
	if got, _ := rowStr(t, db,
		"SELECT root_team_id::text FROM files WHERE id = $1::uuid", f.String(),
	); got.String != team {
		t.Errorf("got file team %q; want %q", got.String, team)
	}
	if got, _ := rowStr(t, db,
		"SELECT root_team_id::text FROM notes WHERE id = $1::uuid", n.String(),
	); got.String != team {
		t.Errorf("got note team %q; want %q", got.String, team)
	}

	// Descendants re-enter the feed under fresh sequence values.
	if seqF1, _ := rowInt(t, db,
		"SELECT seq FROM files WHERE id = $1::uuid", f.String(),
	); seqF1 <= seqF0 {
		t.Errorf("got file seq %d; want > %d", seqF1, seqF0)
	}
	if seqN1, _ := rowInt(t, db,
		"SELECT seq FROM notes WHERE id = $1::uuid", n.String(),
	); seqN1 <= seqN0 {
		t.Errorf("got note seq %d; want > %d", seqN1, seqN0)
	}

	// Moving back to personal cascades a NULL team.
	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 30, assetDoc(x, 3)))
	if got, _ := rowStr(t, db,
		"SELECT root_team_id::text FROM notes WHERE id = $1::uuid", n.String(),
	); got.Valid {
		t.Errorf("got note team %q; want NULL", got.String)
	}
}

func TestTable_DeleteCascade(t *testing.T) {
	db, s, assets, files, notes := setupTables(t)

	owner := uuid.NewV7().String()
	scope := scopeOf(owner)

	x := uuid.NewV7()
	f := uuid.NewV7()
	n := uuid.NewV7()

	applyUpserts(t, s, assets, scope, upsertOp(x, owner, nil, 10, assetDoc(x, 1)))
	applyUpserts(t, s, files, scope, upsertOp(f, owner, nil, 10, fileDoc(f, x)))
	applyUpserts(t, s, notes, scope, upsertOp(n, owner, nil, 10, noteDoc(n, f)))

	applyDeletes(t, s, assets, scope, deleteOp(x, owner, nil, 50))

	for _, table := range []string{"assets", "files", "notes"} {
		if count, _ := rowInt(t, db,
			"SELECT count(*) FROM "+table,
		); count != 0 {
			t.Errorf("table %s: got %d rows; want 0", table, count)
		}
	}

	// All levels are tombstoned under the root's delete timestamp.
	checks := []struct {
		typ string
		id  uuid.UUID
	}{
		{"asset", x},
		{"file", f},
		{"note", n},
	}
	for _, c := range checks {
		hlc, ok := tombstoneHLC(t, db, c.typ, c.id)
		if !ok || hlc != 50 {
			t.Errorf("type %s: got tombstone hlc %d, exists %t; want 50, true",
				c.typ, hlc, ok)
		}
	}
}

func TestTable_FetchWindow(t *testing.T) {
	_, s, assets, _, _ := setupTables(t)

	owner := uuid.NewV7().String()
	scope := scopeOf(owner)

	// Sequential upserts assign seq 1, 2, 3; the absent delete tombstones
	// at seq 4.
	docs := make([]uuid.UUID, 3)
	for i := range docs {
		docs[i] = uuid.NewV7()
		applyUpserts(t, s, assets, scope,
			upsertOp(docs[i], owner, nil, uint64(10+i), assetDoc(docs[i], i)))
	}
	gone := uuid.NewV7()
	applyDeletes(t, s, assets, scope, deleteOp(gone, owner, nil, 20))

	// Full window: live rows and tombstones interleave in seq order.
	all := fetchAll(t, s, assets, scope)
	if got, want := len(all), 4; got != want {
		t.Fatalf("got %d versions; want %d", got, want)
	}
	for i, v := range all {
		if got, want := v.Seq, int64(i+1); got != want {
			t.Errorf("version %d: got seq %d; want %d", i, got, want)
		}
	}
	if all[3].ID != gone || !all[3].Deleted {
		t.Errorf("got last version %v (deleted %t); want tombstone %v",
			all[3].ID, all[3].Deleted, gone)
	}
	if all[0].Deleted || len(all[0].Data) == 0 {
		t.Error("got first version without payload; want live document")
	}

	// Both bounds are exclusive.
	var bounded []diff.Version
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		bounded, err = assets.Fetch(ctx, tx, scope, diff.Window{
			Since: 1,
			Until: 4,
			Limit: 10,
		})
		return err
	})
	if got, want := len(bounded), 2; got != want {
		t.Fatalf("bounded: got %d versions; want %d", got, want)
	}
	if bounded[0].Seq != 2 || bounded[1].Seq != 3 {
		t.Errorf("bounded: got seqs %d, %d; want 2, 3",
			bounded[0].Seq, bounded[1].Seq)
	}

	// The limit caps the page.
	var limited []diff.Version
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		limited, err = assets.Fetch(ctx, tx, scope, diff.Window{
			Since: 0,
			Until: 1 << 60,
			Limit: 2,
		})
		return err
	})
	if got, want := len(limited), 2; got != want {
		t.Fatalf("limited: got %d versions; want %d", got, want)
	}
	if limited[0].Seq != 1 || limited[1].Seq != 2 {
		t.Errorf("limited: got seqs %d, %d; want 1, 2",
			limited[0].Seq, limited[1].Seq)
	}

	// Foreign scopes see nothing.
	foreign := fetchAll(t, s, assets, scopeOf(uuid.NewV7().String()))
	if len(foreign) != 0 {
		t.Errorf("foreign scope: got %d versions; want 0", len(foreign))
	}
}

func TestShares_GrantRevoke(t *testing.T) {
	db, s, assets, files, _ := setupTables(t)
	shares := s.Shares()

	owner := uuid.NewV7().String()
	member := uuid.NewV7().String()
	team := uuid.NewV7().String()

	ownerScope := scopeOf(owner)
	memberScope := scopeOf(member, team)

	// Personal documents of a foreign owner start out invisible.
	x := uuid.NewV7()
	f := uuid.NewV7()
	applyUpserts(t, s, assets, ownerScope,
		upsertOp(x, owner, nil, 10, assetDoc(x, 1)))
	applyUpserts(t, s, files, ownerScope,
		upsertOp(f, owner, nil, 10, fileDoc(f, x)))
	if got := fetchAll(t, s, assets, memberScope); len(got) != 0 {
		t.Fatalf("before grant: got %d versions; want 0", len(got))
	}

	// Granting the team access exposes the owner's personal documents and
	// their descendants.
	grant := uuid.NewV7()
	applyUpserts(t, s, shares, ownerScope,
		upsertOp(grant, owner, &team, 20, "{}"))
	if got := fetchAll(t, s, assets, memberScope); len(got) != 1 ||
		got[0].ID != x {
		t.Errorf("after grant: got assets %v; want [%v]", got, x)
	}
	if got := fetchAll(t, s, files, memberScope); len(got) != 1 ||
		got[0].ID != f {
		t.Errorf("after grant: got files %v; want [%v]", got, f)
	}

	// The grant itself syncs to the team member with a reconstructed
	// payload.
	got := fetchAll(t, s, shares, memberScope)
	if len(got) != 1 || got[0].ID != grant {
		t.Fatalf("after grant: got shares %v; want [%v]", got, grant)
	}
	if data := string(got[0].Data); !strings.Contains(data, owner) ||
		!strings.Contains(data, team) {
		t.Errorf("got share payload %s; want owner and team included", data)
	}

	// Touch re-sequences the owner's personal documents and descendants so
	// they re-enter the feed of the newly granted team.
	seqX0, _ := rowInt(t, db,
		"SELECT seq FROM assets WHERE id = $1::uuid", x.String())
	seqF0, _ := rowInt(t, db,
		"SELECT seq FROM files WHERE id = $1::uuid", f.String())
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		return s.Touch(ctx, tx, owner)
	})
	if seqX1, _ := rowInt(t, db,
		"SELECT seq FROM assets WHERE id = $1::uuid", x.String(),
	); seqX1 <= seqX0 {
		t.Errorf("got asset seq %d; want > %d", seqX1, seqX0)
	}
	if seqF1, _ := rowInt(t, db,
		"SELECT seq FROM files WHERE id = $1::uuid", f.String(),
	); seqF1 <= seqF0 {
		t.Errorf("got file seq %d; want > %d", seqF1, seqF0)
	}

	// Revoking the grant removes the visibility and tombstones the share.
	applyDeletes(t, s, shares, ownerScope, deleteOp(grant, owner, &team, 30))
	if count, _ := rowInt(t, db, "SELECT count(*) FROM diff_shares"); count != 0 {
		t.Errorf("after revoke: got %d shares; want 0", count)
	}
	if _, ok := tombstoneHLC(t, db, "share", grant); !ok {
		t.Error("after revoke: share tombstone should exist")
	}
	if got := fetchAll(t, s, assets, memberScope); len(got) != 0 {
		t.Errorf("after revoke: got %d versions; want 0", len(got))
	}
}

func TestShares_DuplicateGrants(t *testing.T) {
	db, s, _, _, _ := setupTables(t)
	shares := s.Shares()

	owner := uuid.NewV7().String()
	team := uuid.NewV7().String()
	scope := scopeOf(owner)

	// A newer grant for the same (user, team) pair supersedes the older
	// duplicate under a different id.
	g1 := uuid.NewV7()
	applyUpserts(t, s, shares, scope, upsertOp(g1, owner, &team, 10, "{}"))
	g2 := uuid.NewV7()
	applyUpserts(t, s, shares, scope, upsertOp(g2, owner, &team, 20, "{}"))

	if count, _ := rowInt(t, db, "SELECT count(*) FROM diff_shares"); count != 1 {
		t.Fatalf("got %d shares; want 1", count)
	}
	if id, _ := rowStr(t, db,
		"SELECT id::text FROM diff_shares LIMIT 1",
	); id.String != g2.String() {
		t.Errorf("got surviving share %q; want %q", id.String, g2.String())
	}
	if _, ok := tombstoneHLC(t, db, "share", g1); !ok {
		t.Error("superseded duplicate should be tombstoned")
	}

	// A stale duplicate never displaces a newer grant.
	g3 := uuid.NewV7()
	applyUpserts(t, s, shares, scope, upsertOp(g3, owner, &team, 15, "{}"))
	if count, _ := rowInt(t, db, "SELECT count(*) FROM diff_shares"); count != 1 {
		t.Fatalf("after stale duplicate: got %d shares; want 1", count)
	}
	if id, _ := rowStr(t, db,
		"SELECT id::text FROM diff_shares LIMIT 1",
	); id.String != g2.String() {
		t.Errorf("after stale duplicate: got share %q; want %q",
			id.String, g2.String())
	}
}

func TestStore_PruneTombstones(t *testing.T) {
	db, s, assets, _, _ := setupTables(t)

	owner := uuid.NewV7().String()
	scope := scopeOf(owner)

	// Deleting absent documents seeds two tombstones at seq 1 and 2.
	applyDeletes(t, s, assets, scope,
		deleteOp(uuid.NewV7(), owner, nil, 5),
		deleteOp(uuid.NewV7(), owner, nil, 6),
	)

	// Young tombstones survive and the floor stays put.
	n, err := s.PruneTombstones(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("prune: should not have returned an error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d pruned; want 0", n)
	}

	// Aged tombstones are removed and the floor advances past their
	// highest sequence value.
	time.Sleep(20 * time.Millisecond)
	n, err = s.PruneTombstones(context.Background(), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("prune: should not have returned an error: %v", err)
	}
	if n != 2 {
		t.Errorf("got %d pruned; want 2", n)
	}
	if count, _ := rowInt(t, db,
		"SELECT count(*) FROM diff_tombstones",
	); count != 0 {
		t.Errorf("got %d tombstones; want 0", count)
	}
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		floor, err := s.Floor(ctx, tx)
		if err != nil {
			return err
		}
		if floor != 2 {
			t.Errorf("got floor %d; want 2", floor)
		}
		return nil
	})
}
