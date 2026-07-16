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

// Explicitly allow SQL string concatenation:
// #nosec G202

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"slices"
	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/internal/pointer"
)

// tableConfig holds the internal configuration options of a [Table].
type tableConfig struct {
	// schema overrides the store's default schema for this table.
	schema string
	// parent is the table name of the ownership parent (child tables only).
	parent string
	// ref is the column and JSON field referencing the parent row.
	ref string
}

// TableOption configures a single [Table] registration.
type TableOption func(*tableConfig)

// WithTableSchema sets a custom database schema for this table, overriding
// the store's default.
//
// Empty string values are ignored.
func WithTableSchema(name string) TableOption {
	return func(c *tableConfig) {
		if name != "" {
			c.schema = name
		}
	}
}

// WithParent marks the table as a child of the given parent table (by its
// table name, which must already be registered with the store). The ref
// argument names both the child column and the JSON payload field that
// reference the parent row's id; by convention they must be equal.
//
// Empty string values are ignored.
func WithParent(parent, ref string) TableOption {
	return func(c *tableConfig) {
		if parent != "" && ref != "" {
			c.parent = parent
			c.ref = ref
		}
	}
}

// Table implements the [diff.Handler] interface for one entity type backed
// by a single PostgreSQL table. It enforces row-level last-write-wins over
// HLC timestamps, honors tombstones, guards existing rows against
// out-of-scope writers, and cascades team moves and deletions to registered
// child tables.
//
// The backing tables are owned by the application (create them directly or
// via the migrate package) and must match the following shapes.
//
// Root tables:
//
//	CREATE TABLE assets (
//	  id      UUID PRIMARY KEY,
//	  user_id UUID NOT NULL,
//	  team_id UUID,
//	  hlc     BIGINT NOT NULL,
//	  seq     BIGINT NOT NULL,
//	  data    JSONB NOT NULL
//	);
//	CREATE INDEX assets_user_seq ON assets (user_id, seq);
//	CREATE INDEX assets_team_seq ON assets (team_id, seq)
//	  WHERE team_id IS NOT NULL;
//
// Child tables carry the denormalized root identity plus the parent
// reference column named in [WithParent]:
//
//	CREATE TABLE files (
//	  id           UUID PRIMARY KEY,
//	  root_user_id UUID NOT NULL,
//	  root_team_id UUID,
//	  asset_id     UUID NOT NULL,
//	  hlc          BIGINT NOT NULL,
//	  seq          BIGINT NOT NULL,
//	  data         JSONB NOT NULL
//	);
//	CREATE INDEX files_user_seq ON files (root_user_id, seq);
//	CREATE INDEX files_team_seq ON files (root_team_id, seq)
//	  WHERE root_team_id IS NOT NULL;
//
// The owner column (user_id or root_user_id) is immutable: conflicting
// upserts never reassign it. Operation batches must contain at most one
// operation per document; the engine guarantees this via compaction.
type Table struct {
	// store is the owning sync store.
	store *Store
	// typ is the entity type name used in tombstones.
	typ string
	// name is the unquoted table name.
	name string
	// ident is the precomputed, safely quoted schema and table identifier.
	ident string
	// parent links a child table to its ownership parent.
	parent *Table
	// ref is the column (and JSON field) referencing the parent row.
	ref string
	// children lists the tables registered with this table as parent.
	children []*Table
	// userCol and teamCol name the identity columns: user_id/team_id on
	// roots and root_user_id/root_team_id on children.
	userCol string
	teamCol string
	// Precomputed SQL statements.
	upsertSQL   string
	deleteSQL   string
	fetchSQL    string
	resolveSQL  string
	snapshotSQL string
}

// NewTable registers a declarative table handler for one entity type with
// the given store. The typ argument is the entity type name recorded in
// tombstones; table is the backing table's name. Parent tables must be
// registered before their children.
//
// NewTable panics on missing arguments, duplicate registrations, or
// unregistered parent tables (programmer error). Registration is not safe
// for concurrent use; register all tables during startup.
func NewTable(s *Store, typ, name string, opts ...TableOption) *Table {
	if s == nil {
		panic("store is required")
	}
	if typ == "" {
		panic("entity type name is required")
	}
	if name == "" {
		panic("table name is required")
	}
	if _, exists := s.tables[name]; exists {
		panic(fmt.Sprintf("table %q is already registered", name))
	}

	cfg := &tableConfig{schema: s.schema}
	for _, opt := range opts {
		opt(cfg)
	}

	t := &Table{
		store: s,
		typ:   typ,
		name:  name,
		ident: ident(cfg.schema, name),
	}
	if cfg.parent != "" {
		p, ok := s.tables[cfg.parent]
		if !ok {
			panic(fmt.Sprintf("parent table %q is not registered", cfg.parent))
		}
		t.parent = p
		t.ref = cfg.ref
	}
	if t.parent == nil {
		t.userCol, t.teamCol = "user_id", "team_id"
	} else {
		t.userCol, t.teamCol = "root_user_id", "root_team_id"
	}
	t.buildSQL()

	s.tables[name] = t
	s.order = append(s.order, t)
	if t.parent != nil {
		t.parent.children = append(t.parent.children, t)
	}
	return t
}

// buildSQL precomputes the statements of the handler methods.
func (t *Table) buildSQL() {
	s := t.store
	tomb := s.identTombstones

	// The insert column list, select list, and conflict assignments differ
	// between root and child tables: children additionally extract the
	// parent reference from the JSON payload, and their identity columns
	// carry the denormalized root identity.
	cols := "id, " + t.userCol + ", " + t.teamCol + ", hlc, seq, data"
	sel := "a.id, a.user_id, a.team_id, a.hlc, " + s.nextval + ", a.data"
	set := t.teamCol + " = EXCLUDED." + t.teamCol + "," +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq, data = EXCLUDED.data"
	if t.parent != nil {
		refCol := escape(t.ref)
		cols = "id, " + t.userCol + ", " + t.teamCol + ", " + refCol +
			", hlc, seq, data"
		sel = "a.id, a.user_id, a.team_id, (a.data ->> " + literal(t.ref) +
			")::uuid, a.hlc, " + s.nextval + ", a.data"
		set = t.teamCol + " = EXCLUDED." + t.teamCol + "," +
			" " + refCol + " = EXCLUDED." + refCol + "," +
			" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq, data = EXCLUDED.data"
	}
	guard := "(d." + t.userCol + " = $7::uuid" +
		" OR d." + t.teamCol + " = ANY($8::uuid[]))"

	t.upsertSQL = "WITH incoming AS (" +
		" SELECT t.id, t.user_id, nullif(t.team_id, '')::uuid AS team_id," +
		" t.hlc, t.data" +
		" FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::bigint[]," +
		" $5::jsonb[]) AS t(id, user_id, team_id, hlc, data)" +
		"), alive AS (" +
		" SELECT i.* FROM incoming i" +
		" LEFT JOIN " + tomb + " ts ON ts.type = $6::text AND ts.id = i.id" +
		" WHERE ts.id IS NULL OR i.hlc > ts.hlc" +
		"), cleared AS (" +
		" DELETE FROM " + tomb + " ts USING alive a" +
		" WHERE ts.type = $6::text AND ts.id = a.id" +
		") INSERT INTO " + t.ident + " AS d (" + cols + ")" +
		" SELECT " + sel + " FROM alive a" +
		" ON CONFLICT (id) DO UPDATE SET " + set +
		" WHERE EXCLUDED.hlc > d.hlc AND " + guard +
		" RETURNING d.id::text, d." + t.teamCol + "::text"

	t.deleteSQL = "WITH incoming AS (" +
		" SELECT t.id, t.hlc, t.user_id, nullif(t.team_id, '')::uuid AS team_id" +
		" FROM unnest($1::uuid[], $2::bigint[], $3::uuid[], $4::text[])" +
		" AS t(id, hlc, user_id, team_id)" +
		"), victims AS (" +
		" DELETE FROM " + t.ident + " a USING incoming i" +
		" WHERE a.id = i.id AND a.hlc < i.hlc" +
		" AND (a." + t.userCol + " = $5::uuid" +
		" OR a." + t.teamCol + " = ANY($6::uuid[]))" +
		" RETURNING a.id, a." + t.userCol + " AS user_id," +
		" a." + t.teamCol + " AS team_id, i.hlc" +
		"), scoped AS (" +
		" SELECT id, user_id, team_id, hlc FROM victims" +
		" UNION ALL" +
		" SELECT i.id, i.user_id, i.team_id, i.hlc FROM incoming i" +
		" WHERE NOT EXISTS (" +
		" SELECT 1 FROM " + t.ident + " a WHERE a.id = i.id" +
		")" +
		") INSERT INTO " + tomb + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $7::text, id, user_id, team_id, hlc, " + s.nextval +
		" FROM scoped" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc" +
		" RETURNING ts.id::text, ts.user_id::text, ts.team_id::text, ts.hlc"

	// Personal documents of foreign owners become visible through share
	// grants issued to any of the caller's teams.
	granted := "SELECT user_id FROM " + s.identShares +
		" WHERE team_id = ANY($2::uuid[])"
	visible := "(" + t.userCol + " = $1::uuid" +
		" OR " + t.teamCol + " = ANY($2::uuid[])" +
		" OR (" + t.teamCol + " IS NULL" +
		" AND " + t.userCol + " IN (" + granted + ")))"
	buried := "(user_id = $1::uuid" +
		" OR team_id = ANY($2::uuid[])" +
		" OR (team_id IS NULL AND user_id IN (" + granted + ")))"

	t.fetchSQL = "(SELECT id::text, seq, FALSE AS deleted, data" +
		" FROM " + t.ident +
		" WHERE " + visible + " AND seq > $3 AND seq < $4" +
		" UNION ALL" +
		" SELECT id::text, seq, TRUE AS deleted, NULL::jsonb AS data" +
		" FROM " + tomb +
		" WHERE type = $5::text AND " + buried +
		" AND seq > $3 AND seq < $4" +
		") ORDER BY seq LIMIT $6"

	t.resolveSQL = "SELECT id::text, " + t.userCol + "::text," +
		" " + t.teamCol + "::text FROM " + t.ident +
		" WHERE id = ANY($1::uuid[])"

	t.snapshotSQL = "SELECT id::text, " + t.teamCol + "::text FROM " +
		t.ident + " WHERE id = ANY($1::uuid[])"
}

// Upsert implements the [diff.Handler] interface. It applies
// create-or-replace operations in bulk with row-level last-write-wins:
// tombstones block stale upserts and are cleared by newer ones
// (resurrection), conflicting rows only yield to strictly newer timestamps,
// existing rows must lie inside the caller's scope, and the owner column is
// never reassigned. Team moves cascade to all descendant tables, updating
// their denormalized root identity and re-sequencing the affected rows.
func (t *Table) Upsert(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	if len(ops) == 0 {
		return nil
	}

	n := len(ops)
	ids := make([]string, n)
	users := make([]string, n)
	teams := make([]string, n)
	hlcs := make([]int64, n)
	datas := make([]string, n)
	for i, op := range ops {
		ids[i] = op.Meta.ID.String()
		users[i] = op.Meta.UserID
		teams[i] = pointer.Value(op.Meta.TeamID)
		hlcs[i] = int64(op.Time)
		datas[i] = string(op.Data)
	}

	// Snapshot the current team assignments so team moves can be detected
	// after the upsert. The engine holds the scope's advisory locks, so no
	// concurrent writer can interleave.
	var before map[string]sql.NullString
	if len(t.children) > 0 {
		var err error
		if before, err = t.snapshot(ctx, tx, ids); err != nil {
			return err
		}
	}

	rows, err := tx.QueryContext(ctx, t.upsertSQL,
		ids, users, teams, hlcs, datas,
		t.typ, scope.UserID, scope.Teams,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert documents: %w", err)
	}
	after, err := scanStates(rows, t.store.logger)
	if err != nil {
		return err
	}

	if len(t.children) == 0 {
		return nil
	}
	for _, st := range after {
		old, existed := before[st.id]
		if !existed || old == st.team {
			continue // fresh insert or unchanged team
		}
		if err := t.cascadeTeam(ctx, tx, st.id, st.team); err != nil {
			return err
		}
	}
	return nil
}

// snapshot returns the current team assignment of the given rows.
func (t *Table) snapshot(
	ctx context.Context,
	tx *sql.Tx,
	ids []string,
) (map[string]sql.NullString, error) {
	rows, err := tx.QueryContext(ctx, t.snapshotSQL, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to snapshot documents: %w", err)
	}
	states, err := scanStates(rows, t.store.logger)
	if err != nil {
		return nil, err
	}
	out := make(map[string]sql.NullString, len(states))
	for _, st := range states {
		out[st.id] = st.team
	}
	return out, nil
}

// state pairs a document ID with its team assignment.
type state struct {
	id   string
	team sql.NullString
}

// scanStates consumes rows of the shape (id, team_id).
func scanStates(rows *sql.Rows, logger *slog.Logger) ([]state, error) {
	defer closeRows(rows, logger)

	var out []state
	for rows.Next() {
		var st state
		if err := rows.Scan(&st.id, &st.team); err != nil {
			return nil, fmt.Errorf("failed to scan document state: %w", err)
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read document states: %w", err)
	}
	return out, nil
}

// Delete implements the [diff.Handler] interface. It removes documents and
// records tombstones in bulk: only strictly newer timestamps delete an
// existing in-scope row (tombstoning the row's stored identity), deletes of
// absent documents tombstone the payload identity, and stale deletes are
// skipped entirely. Deletions cascade to all descendant tables under the
// same timestamp.
func (t *Table) Delete(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	if len(ops) == 0 {
		return nil
	}

	n := len(ops)
	ids := make([]string, n)
	hlcs := make([]int64, n)
	users := make([]string, n)
	teams := make([]string, n)
	for i, op := range ops {
		ids[i] = op.Meta.ID.String()
		hlcs[i] = int64(op.Time)
		users[i] = op.Meta.UserID
		teams[i] = pointer.Value(op.Meta.TeamID)
	}

	rows, err := tx.QueryContext(ctx, t.deleteSQL,
		ids, hlcs, users, teams,
		scope.UserID, scope.Teams, t.typ,
	)
	if err != nil {
		return fmt.Errorf("failed to delete documents: %w", err)
	}

	type victim struct {
		id   string
		user string
		team sql.NullString
		hlc  int64
	}
	victims, err := func() ([]victim, error) {
		defer closeRows(rows, t.store.logger)
		var out []victim
		for rows.Next() {
			var v victim
			if err := rows.Scan(&v.id, &v.user, &v.team, &v.hlc); err != nil {
				return nil, fmt.Errorf("failed to scan deleted document: %w", err)
			}
			out = append(out, v)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("failed to read deleted documents: %w", err)
		}
		return out, nil
	}()
	if err != nil {
		return err
	}

	if len(t.children) == 0 {
		return nil
	}
	for _, v := range victims {
		err := t.cascadeDelete(ctx, tx, v.id, v.user, v.team, v.hlc)
		if err != nil {
			return err
		}
	}
	return nil
}

// Fetch implements the [diff.Handler] interface. It returns live versions
// and tombstones visible to the scope within the window, in ascending
// sequence order: the caller's own documents, their teams' documents, and
// foreign personal documents shared with any of their teams.
func (t *Table) Fetch(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	w diff.Window,
) ([]diff.Version, error) {
	rows, err := tx.QueryContext(ctx, t.fetchSQL,
		scope.UserID,
		scope.Teams,
		w.Since,
		w.Until,
		t.typ,
		w.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch documents: %w", err)
	}
	return collect(rows, t.store.logger)
}

// Resolve implements the [diff.Handler] interface. For child tables, the
// returned envelopes carry the denormalized root identity.
func (t *Table) Resolve(
	ctx context.Context,
	tx *sql.Tx,
	ids []uuid.UUID,
) (map[uuid.UUID]diff.Meta, error) {
	return resolve(ctx, tx, t.resolveSQL, ids, t.store.logger)
}

// descendant pairs a descendant table with the SQL condition selecting its
// rows under a single root row id bound to $1.
type descendant struct {
	table *Table
	cond  string
}

// descendants walks the registered child tables recursively and returns
// them in parent-first order, each with a condition chaining through the
// intermediate parent tables down from the root row id bound to $1.
func (t *Table) descendants() []descendant {
	var out []descendant
	var walk func(c *Table, cond string)
	walk = func(c *Table, cond string) {
		out = append(out, descendant{table: c, cond: cond})
		sub := "SELECT id FROM " + c.ident + " WHERE " + cond
		for _, gc := range c.children {
			walk(gc, escape(gc.ref)+" IN ("+sub+")")
		}
	}
	for _, c := range t.children {
		walk(c, escape(c.ref)+" = $1::uuid")
	}
	return out
}

// cascadeTeam propagates a root team move to all descendant rows, updating
// their denormalized root identity and re-sequencing them so they re-enter
// the patch feed.
func (t *Table) cascadeTeam(
	ctx context.Context,
	tx *sql.Tx,
	rootID string,
	team sql.NullString,
) error {
	for _, d := range t.descendants() {
		query := "UPDATE " + d.table.ident +
			" SET root_team_id = nullif($2, '')::uuid," +
			" seq = " + t.store.nextval +
			" WHERE " + d.cond
		if _, err := tx.ExecContext(ctx, query, rootID, team.String); err != nil {
			return fmt.Errorf(
				"failed to cascade team move to table %q: %w",
				d.table.name, err,
			)
		}
	}
	return nil
}

// cascadeDelete removes all descendant rows of a deleted root row and
// tombstones them under the root's identity and delete timestamp. Deeper
// tables are processed first so the conditions chaining through their
// parents still find the intermediate rows.
func (t *Table) cascadeDelete(
	ctx context.Context,
	tx *sql.Tx,
	rootID string,
	user string,
	team sql.NullString,
	hlc int64,
) error {
	ds := t.descendants()
	for _, d := range slices.Backward(ds) {
		query := "WITH doomed AS (" +
			" DELETE FROM " + d.table.ident +
			" WHERE " + d.cond +
			" RETURNING id" +
			") INSERT INTO " + t.store.identTombstones + " AS ts" +
			" (type, id, user_id, team_id, hlc, seq)" +
			" SELECT $2::text, id, $3::uuid, nullif($4, '')::uuid," +
			" $5::bigint, " + t.store.nextval +
			" FROM doomed" +
			" ON CONFLICT (type, id) DO UPDATE SET" +
			" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
			" WHERE EXCLUDED.hlc > ts.hlc"
		if _, err := tx.ExecContext(ctx, query,
			rootID, d.table.typ, user, team.String, hlc,
		); err != nil {
			return fmt.Errorf(
				"failed to cascade deletion to table %q: %w",
				d.table.name, err,
			)
		}
	}
	return nil
}

var _ diff.Handler[*sql.Tx] = (*Table)(nil)
