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
	"github.com/deep-rent/nexus/internal/quote"
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

// Table implements the [diff.Handler] interface for one document model
// backed by a single PostgreSQL table. It enforces row-level
// last-write-wins over HLC timestamps, honors tombstones, guards existing
// rows against out-of-scope writers, and cascades team moves and deletions
// to registered child tables.
//
// The backing tables are owned by the application (create them through your
// own schema migrations) and must match the following shapes. The feed scan
// is a union of independently indexable visibility branches, so each table
// needs three indexes: one for the caller's own documents, a partial one
// for team documents, and a partial one for personal documents reached
// through share grants.
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
//	CREATE INDEX assets_personal_seq ON assets (user_id, seq)
//	  WHERE team_id IS NULL;
//
// Child tables carry the denormalized root identity plus the parent
// reference column named in [WithParent], which needs its own index for the
// cascade scans:
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
//	CREATE INDEX files_personal_seq ON files (root_user_id, seq)
//	  WHERE root_team_id IS NULL;
//	CREATE INDEX files_asset ON files (asset_id);
//
// Foreign keys from the identity columns (user_id/team_id and
// root_user_id/root_team_id) to the application's users and teams tables
// are recommended. Foreign keys BETWEEN synced document tables, however,
// remain unsupported: offline clients may split a parent and its children
// across separate pushes, so a child row can arrive before its parent.
//
// The owner column (user_id or root_user_id) is immutable: conflicting
// upserts never reassign it. On child tables, the parent reference may only
// move between roots of the SAME owner; re-parenting a child under a root
// with a different owner is silently skipped, like any other out-of-scope
// write. Operation batches must contain at most one operation per document;
// the engine guarantees this via compaction.
//
// When a write changes a row's team assignment (directly, or via the team
// move cascade), the row's previous audience receives a move tombstone
// carrying the old identity under the move's timestamp: departed clients
// delete the document, while clients that also receive the new version in
// the same page keep it (equal-time updates beat deletions in the client
// contract).
type Table struct {
	// store is the owning sync store.
	store *Store
	// model is the registered model name recorded in tombstones. It must
	// equal the name the table is registered under in the engine's registry.
	model string
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
	burySQL     string
	fetchSQL    string
	resolveSQL  string
	snapshotSQL string
	reseqSQL    string
}

// NewTable registers a declarative table handler for one document model
// with the given store. The model argument is recorded in tombstones and
// MUST equal the model name the handler is registered under in the engine's
// registry; name is the backing table's name. Parent tables must be
// registered before their children.
//
// NewTable panics on missing arguments, duplicate registrations, or
// unregistered parent tables (programmer error). Registration is not safe
// for concurrent use; register all tables during startup.
func NewTable(s *Store, model, name string, opts ...TableOption) *Table {
	if s == nil {
		panic("store is required")
	}
	if model == "" {
		panic("model name is required")
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
		model: model,
		name:  name,
		ident: quote.Ident(cfg.schema, name),
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
	guard := "(d." + t.userCol + " = $7::uuid" +
		" OR d." + t.teamCol + " = ANY($8::uuid[]))"
	if t.parent != nil {
		refCol := quote.Escape(t.ref)
		cols = "id, " + t.userCol + ", " + t.teamCol + ", " + refCol +
			", hlc, seq, data"
		sel = "a.id, a.user_id, a.team_id, (a.data ->> " + quote.Literal(t.ref) +
			")::uuid, a.hlc, " + s.nextval + ", a.data"
		set = t.teamCol + " = EXCLUDED." + t.teamCol + "," +
			" " + refCol + " = EXCLUDED." + refCol + "," +
			" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq, data = EXCLUDED.data"
		// Re-parenting a child under a root with a different owner is
		// silently skipped, like the hijack guard above.
		guard += " AND d." + t.userCol + " = EXCLUDED." + t.userCol
	}

	// A tombstone may only be bypassed (resurrection) when its identity
	// lies within the caller's scope or the row is still alive (then the
	// tombstone records a past team move and the conflict guard governs);
	// clearing it additionally requires the row to be dead, so departure
	// tombstones of live rows survive for late syncers.
	t.upsertSQL = "WITH incoming AS (" +
		" SELECT t.id, t.user_id, nullif(t.team_id, '')::uuid AS team_id," +
		" t.hlc, t.data" +
		" FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::bigint[]," +
		" $5::jsonb[]) AS t(id, user_id, team_id, hlc, data)" +
		"), alive AS (" +
		" SELECT i.* FROM incoming i" +
		" LEFT JOIN " + tomb + " ts ON ts.type = $6::text AND ts.id = i.id" +
		" LEFT JOIN " + t.ident + " r ON r.id = i.id" +
		" WHERE ts.id IS NULL OR (i.hlc > ts.hlc" +
		" AND (r.id IS NOT NULL" +
		" OR ts.user_id = $7::uuid OR ts.team_id = ANY($8::uuid[])))" +
		"), cleared AS (" +
		" DELETE FROM " + tomb + " ts USING alive a" +
		" WHERE ts.type = $6::text AND ts.id = a.id" +
		" AND (ts.user_id = $7::uuid OR ts.team_id = ANY($8::uuid[]))" +
		" AND NOT EXISTS (" +
		" SELECT 1 FROM " + t.ident + " r WHERE r.id = a.id" +
		")" +
		") INSERT INTO " + t.ident + " AS d (" + cols + ")" +
		" SELECT " + sel + " FROM alive a" +
		" ON CONFLICT (id) DO UPDATE SET " + set +
		" WHERE EXCLUDED.hlc > d.hlc AND " + guard +
		" RETURNING d.id::text, d." + t.userCol + "::text," +
		" d." + t.teamCol + "::text, d.hlc"

	// The scoped variant backs Delete; the unscoped variant backs the
	// backend-write helper Bury. Their argument lists differ: the scope
	// occupies $5 and $6 in the scoped variant, shifting the model name.
	remove := func(guard, model string) string {
		return "WITH incoming AS (" +
			" SELECT t.id, t.hlc, t.user_id, nullif(t.team_id, '')::uuid AS team_id" +
			" FROM unnest($1::uuid[], $2::bigint[], $3::uuid[], $4::text[])" +
			" AS t(id, hlc, user_id, team_id)" +
			"), victims AS (" +
			" DELETE FROM " + t.ident + " a USING incoming i" +
			" WHERE a.id = i.id AND a.hlc < i.hlc" + guard +
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
			" SELECT " + model + "::text, id, user_id, team_id, hlc, " + s.nextval +
			" FROM scoped" +
			" ON CONFLICT (type, id) DO UPDATE SET" +
			" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
			" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
			" WHERE EXCLUDED.hlc > ts.hlc" +
			" RETURNING ts.id::text, ts.user_id::text, ts.team_id::text, ts.hlc"
	}
	t.deleteSQL = remove(
		" AND (a."+t.userCol+" = $5::uuid"+
			" OR a."+t.teamCol+" = ANY($6::uuid[]))",
		"$7",
	)
	t.burySQL = remove("", "$5")

	// The feed scan unions independently indexable visibility branches: the
	// caller's own documents, their teams' documents, and foreign personal
	// documents shared with any of their teams through live grants. The
	// tombstone half mirrors the same three branches.
	granted := "SELECT user_id FROM " + s.identShares +
		" WHERE team_id = ANY($2::uuid[])"
	live := func(cond string) string {
		return "SELECT id::text, seq, hlc, FALSE AS deleted, data" +
			" FROM " + t.ident +
			" WHERE " + cond + " AND seq > $3 AND seq < $4"
	}
	dead := func(cond string) string {
		return "SELECT id::text, seq, hlc, TRUE AS deleted, NULL::jsonb AS data" +
			" FROM " + tomb +
			" WHERE type = $5::text AND " + cond +
			" AND seq > $3 AND seq < $4"
	}
	t.fetchSQL = "(" +
		live(t.userCol+" = $1::uuid") +
		" UNION ALL " +
		live(t.teamCol+" = ANY($2::uuid[])"+
			" AND "+t.userCol+" <> $1::uuid") +
		" UNION ALL " +
		live(t.teamCol+" IS NULL AND "+t.userCol+" <> $1::uuid"+
			" AND "+t.userCol+" IN ("+granted+")") +
		" UNION ALL " +
		dead("user_id = $1::uuid") +
		" UNION ALL " +
		dead("team_id = ANY($2::uuid[]) AND user_id <> $1::uuid") +
		" UNION ALL " +
		dead("team_id IS NULL AND user_id <> $1::uuid"+
			" AND user_id IN ("+granted+")") +
		") ORDER BY seq LIMIT $6"

	t.resolveSQL = "SELECT id::text, " + t.userCol + "::text," +
		" " + t.teamCol + "::text FROM " + t.ident +
		" WHERE id = ANY($1::uuid[])"

	t.snapshotSQL = "SELECT id::text, " + t.teamCol + "::text FROM " +
		t.ident + " WHERE id = ANY($1::uuid[])"

	t.reseqSQL = "UPDATE " + t.ident + " SET seq = " + s.nextval +
		" WHERE id = ANY($1::uuid[])"
}

// Upsert implements the [diff.Handler] interface. It applies
// create-or-replace operations in bulk with row-level last-write-wins:
// tombstones block stale upserts and are cleared by newer ones
// (resurrection, permitted only within the tombstone's identity scope),
// conflicting rows only yield to strictly newer timestamps, existing rows
// must lie inside the caller's scope, and the owner column is never
// reassigned. Team moves leave a move tombstone for the departed audience
// and cascade to all descendant tables, updating their denormalized root
// identity and re-sequencing the affected rows.
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
	before, err := t.snapshot(ctx, tx, ids)
	if err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, t.upsertSQL,
		ids, users, teams, hlcs, datas,
		t.model, scope.UserID, scope.Teams,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert documents: %w", err)
	}
	after, err := scanStamps(rows, t.store.logger)
	if err != nil {
		return err
	}

	// Rows whose team assignment changed depart their previous audience:
	// bury the old identity under the move's timestamp, and propagate the
	// move to all descendant rows.
	var moves []move
	var moved []stamp
	for _, st := range after {
		old, existed := before[st.id]
		if !existed || old == st.team {
			continue // fresh insert or unchanged team
		}
		moves = append(moves, move{
			id:   st.id,
			user: st.user,
			team: old.String,
			hlc:  st.hlc,
		})
		moved = append(moved, st)
	}
	if len(moves) == 0 {
		return nil
	}
	if err := t.store.entomb(ctx, tx, t.model, moves); err != nil {
		return err
	}
	if len(t.children) == 0 {
		return nil
	}
	return t.cascadeTeam(ctx, tx, moved)
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
	defer close(rows, logger)

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
	ids, hlcs, users, teams := deleteArgs(ops)
	return t.remove(ctx, tx, t.deleteSQL,
		ids, hlcs, users, teams, scope.UserID, scope.Teams, t.model,
	)
}

// Bury is the backend-write counterpart of [Table.Delete]: it removes the
// given documents and records tombstones under the identities and
// timestamps carried by ops, cascading to all descendant tables, but
// without any scope checks. Use it for server-initiated deletions of synced
// rows; callers must hold the scope's advisory locks (see [Store.Mutate])
// and stamp the operations with fresh engine timestamps.
func (t *Table) Bury(
	ctx context.Context,
	tx *sql.Tx,
	ops []diff.Op,
) error {
	if len(ops) == 0 {
		return nil
	}
	ids, hlcs, users, teams := deleteArgs(ops)
	return t.remove(ctx, tx, t.burySQL, ids, hlcs, users, teams, t.model)
}

// deleteArgs renders delete operations into the parallel array parameters
// shared by Delete and Bury.
func deleteArgs(ops []diff.Op) ([]string, []int64, []string, []string) {
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
	return ids, hlcs, users, teams
}

// remove executes a delete statement and cascades the recorded tombstones
// to all descendant tables.
func (t *Table) remove(
	ctx context.Context,
	tx *sql.Tx,
	query string,
	args ...any,
) error {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete documents: %w", err)
	}
	victims, err := scanStamps(rows, t.store.logger)
	if err != nil {
		return err
	}

	if len(t.children) == 0 || len(victims) == 0 {
		return nil
	}
	return t.cascadeDelete(ctx, tx, victims)
}

// Reseq assigns fresh feed sequence values to the given rows so they
// re-enter the patch feed. It is the companion of [Store.Mutate] for
// backend-initiated updates of synced rows; callers must hold the scope's
// advisory locks.
func (t *Table) Reseq(
	ctx context.Context,
	tx *sql.Tx,
	ids []uuid.UUID,
) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, t.reseqSQL, toStrings(ids)); err != nil {
		return fmt.Errorf("failed to reseq documents: %w", err)
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
		t.model,
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
// rows under the root row ids exposed by a relation aliased r; the
// descendant table itself is aliased c.
type descendant struct {
	table *Table
	cond  string
}

// descendants walks the registered child tables recursively and returns
// them in parent-first order, each with a condition chaining through the
// intermediate parent tables down from the root rows r.
func (t *Table) descendants() []descendant {
	var out []descendant
	var walk func(c *Table, parents string, depth int)
	walk = func(c *Table, parents string, depth int) {
		out = append(out, descendant{
			table: c,
			cond:  "c." + quote.Escape(c.ref) + parents,
		})
		alias := fmt.Sprintf("p%d", depth)
		sub := " IN (SELECT " + alias + ".id FROM " + c.ident + " " + alias +
			" WHERE " + alias + "." + quote.Escape(c.ref) + parents + ")"
		for _, gc := range c.children {
			walk(gc, sub, depth+1)
		}
	}
	for _, c := range t.children {
		walk(c, " = r.id", 1)
	}
	return out
}

// cascadeTeam propagates root team moves to all descendant rows in bulk:
// one statement per descendant table updates the denormalized root
// identity, re-sequences the affected rows so they re-enter the patch feed,
// and buries each row's previous identity under the move's timestamp for
// the departed audience.
func (t *Table) cascadeTeam(
	ctx context.Context,
	tx *sql.Tx,
	moved []stamp,
) error {
	n := len(moved)
	ids := make([]string, n)
	teams := make([]string, n)
	hlcs := make([]int64, n)
	for i, m := range moved {
		ids[i] = m.id
		teams[i] = m.team.String // NULL scans to the empty string
		hlcs[i] = m.hlc
	}

	for _, d := range t.descendants() {
		// The self-join against o captures the pre-update root identity for
		// the move tombstones: within one statement, o reads the snapshot
		// taken at statement start.
		query := "WITH roots AS (" +
			" SELECT r.id, nullif(r.team, '')::uuid AS team, r.hlc" +
			" FROM unnest($1::uuid[], $2::text[], $3::bigint[])" +
			" AS r(id, team, hlc)" +
			"), moved AS (" +
			" UPDATE " + d.table.ident + " c" +
			" SET " + d.table.teamCol + " = r.team, seq = " + t.store.nextval +
			" FROM roots r, " + d.table.ident + " o" +
			" WHERE o.id = c.id AND " + d.cond +
			" RETURNING c.id, o." + d.table.userCol + " AS user_id," +
			" o." + d.table.teamCol + " AS team_id, r.hlc" +
			") INSERT INTO " + t.store.identTombstones + " AS ts" +
			" (type, id, user_id, team_id, hlc, seq)" +
			" SELECT $4::text, id, user_id, team_id, hlc, " + t.store.nextval +
			" FROM moved" +
			" ON CONFLICT (type, id) DO UPDATE SET" +
			" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
			" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
			" WHERE EXCLUDED.hlc > ts.hlc"
		if _, err := tx.ExecContext(ctx, query,
			ids, teams, hlcs, d.table.model,
		); err != nil {
			return fmt.Errorf(
				"failed to cascade team move to table %q: %w",
				d.table.name, err,
			)
		}
	}
	return nil
}

// cascadeDelete removes all descendant rows of the deleted root rows in
// bulk and tombstones them under the root's identity and delete timestamp:
// one statement per descendant table. Deeper tables are processed first so
// the conditions chaining through their parents still find the intermediate
// rows.
func (t *Table) cascadeDelete(
	ctx context.Context,
	tx *sql.Tx,
	victims []stamp,
) error {
	n := len(victims)
	ids := make([]string, n)
	users := make([]string, n)
	teams := make([]string, n)
	hlcs := make([]int64, n)
	for i, v := range victims {
		ids[i] = v.id
		users[i] = v.user
		teams[i] = v.team.String // NULL scans to the empty string
		hlcs[i] = v.hlc
	}

	ds := t.descendants()
	for _, d := range slices.Backward(ds) {
		query := "WITH roots AS (" +
			" SELECT r.id, r.user_id, nullif(r.team, '')::uuid AS team_id, r.hlc" +
			" FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::bigint[])" +
			" AS r(id, user_id, team, hlc)" +
			"), doomed AS (" +
			" DELETE FROM " + d.table.ident + " c USING roots r" +
			" WHERE " + d.cond +
			" RETURNING c.id, r.user_id, r.team_id, r.hlc" +
			") INSERT INTO " + t.store.identTombstones + " AS ts" +
			" (type, id, user_id, team_id, hlc, seq)" +
			" SELECT $5::text, id, user_id, team_id, hlc, " + t.store.nextval +
			" FROM doomed" +
			" ON CONFLICT (type, id) DO UPDATE SET" +
			" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
			" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
			" WHERE EXCLUDED.hlc > ts.hlc"
		if _, err := tx.ExecContext(ctx, query,
			ids, users, teams, hlcs, d.table.model,
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
