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
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/dat/diff"
	"github.com/deep-rent/nexus/dat/diff/hlc"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/std/quote"
)


// zeroUUID is the SQL literal of the zero UUID, the sentinel for personal
// documents: NULL team columns read as the zero UUID and vice versa.
const zeroUUID = "'00000000-0000-0000-0000-000000000000'::uuid"


// Store implements the [diff.Store] interface for PostgreSQL.
//
// It provides the shared transactional machinery of the sync engine and
// acts as the registration hub for the [Table] handlers of the individual
// models. Table registration via [NewTable] is not safe for concurrent
// use; register all tables during startup, before serving.
//
// The bookkeeping schema must be provisioned by the application before the
// store is used; the SQL files under migrations/ document the expected
// shape and serve as reference material.
type Store struct {
	db         *sql.DB           // underlying database connection pool
	schema     string            // unquoted default schema
	mutations  string            // precomputed, safely quoted identifier
	tombstones string            // precomputed, safely quoted identifier
	state      string            // precomputed, safely quoted identifier
	shares     string            // precomputed, safely quoted identifier
	sequence   string            // precomputed, safely quoted identifier
	nextval    string            // nextval() expression of the feed sequence
	logger     *slog.Logger      // records store operations
	tables     map[string]*Table // indexes all registered tables by their name
	order      []*Table          // lists tables in registration order
	// Note: Parent tables always precede their children.
}

// New creates a new PostgreSQL sync store around the given connection pool
// and options. It panics if the given pool is nil (programmer error).
func New(db *sql.DB, opts ...Option) *Store {
	if db == nil {
		panic("db is required")
	}

	cfg := &config{
		schema:     DefaultSchema,
		mutations:  DefaultMutationsTable,
		tombstones: DefaultTombstonesTable,
		state:      DefaultStateTable,
		shares:     DefaultSharesTable,
		sequence:   DefaultSequence,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	s := &Store{
		db:         db,
		schema:     cfg.schema,
		mutations:  quote.Ident(cfg.schema, cfg.mutations),
		tombstones: quote.Ident(cfg.schema, cfg.tombstones),
		state:      quote.Ident(cfg.schema, cfg.state),
		shares:     quote.Ident(cfg.schema, cfg.shares),
		sequence:   quote.Ident(cfg.schema, cfg.sequence),
		logger:     cfg.logger,
		tables:     make(map[string]*Table),
	}
	s.nextval = "nextval(" + quote.Literal(s.sequence) + ")"

	return s
}

// Exec implements the [diff.Store] interface. It runs fn within a single
// read-committed transaction, committing on nil and rolling back on error.
func (s *Store) Exec(
	ctx context.Context,
	fn func(ctx context.Context, tx *sql.Tx) error,
) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if e := tx.Rollback(); e != nil && !errors.Is(e, sql.ErrTxDone) {
			s.logger.Error(
				"Failed to rollback transaction",
				log.Err(e),
			)
		}
	}()

	if err := fn(ctx, tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// Lock implements the [diff.Store] interface. It acquires transaction-
// scoped advisory locks on the given keys: shared locks for keys the
// request only reads, exclusive locks for keys it writes. A key listed in
// both sets is locked exclusively. All keys are deduplicated and acquired
// in one global ascending order, regardless of mode, so concurrent callers
// never deadlock.
func (s *Store) Lock(
	ctx context.Context,
	tx *sql.Tx,
	shared, exclusive []uuid.UUID,
) error {
	// Fold both sets into one mode map; exclusive wins on overlap.
	modes := make(map[int64]bool, len(shared)+len(exclusive))
	for _, key := range shared {
		k := lockKey(key)
		if _, exists := modes[k]; !exists {
			modes[k] = false
		}
	}
	for _, key := range exclusive {
		modes[lockKey(key)] = true
	}
	if len(modes) == 0 {
		return nil
	}

	keys := make([]int64, 0, len(modes))
	for k := range modes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	excl := make([]bool, len(keys))
	for i, k := range keys {
		excl[i] = modes[k]
	}

	// Single round trip. The ORDER BY inside the subquery both sorts the
	// keys server-side and, because a sort clause blocks subquery pull-up,
	// forces the planner to keep the subquery as a separate scan node: the
	// volatile lock functions in the outer target list are then evaluated
	// row by row in ascending key order. This is the shape the PostgreSQL
	// documentation prescribes for set-oriented advisory locking. CASE
	// evaluates only the selected branch, so each key is locked in exactly
	// one mode.
	query := "SELECT CASE WHEN k.excl" +
		" THEN pg_advisory_xact_lock(k.key) IS NOT NULL" +
		" ELSE pg_advisory_xact_lock_shared(k.key) IS NOT NULL END" +
		" FROM (SELECT t.key, t.excl" +
		" FROM unnest($1::bigint[], $2::boolean[]) AS t(key, excl)" +
		" ORDER BY t.key) k"
	if _, err := tx.ExecContext(ctx, query, keys, excl); err != nil {
		return fmt.Errorf("failed to acquire advisory locks: %w", err)
	}
	return nil
}

// lockKey derives a positive 64-bit advisory lock key from an opaque scope
// identifier.
func lockKey(key uuid.UUID) int64 {
	h := sha256.New()
	h.Write([]byte("diff:scope:"))
	h.Write(key[:])
	sum := h.Sum(nil)
	return int64(binary.BigEndian.Uint64(sum[:8]) & 0x7FFFFFFFFFFFFFFF)
}

// Floor implements the [diff.Store] interface. It returns the retention
// floor, or 0 if the state row is missing.
func (s *Store) Floor(ctx context.Context, tx *sql.Tx) (int64, error) {
	query := "SELECT seq FROM " + s.state + " WHERE key = 'floor'"
	var seq int64
	err := tx.QueryRowContext(ctx, query).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to read retention floor: %w", err)
	}
	return seq, nil
}

// Barrier implements the [diff.Store] interface. It consumes and returns
// the next feed sequence value.
func (s *Store) Barrier(ctx context.Context, tx *sql.Tx) (int64, error) {
	var seq int64
	err := tx.QueryRowContext(ctx, "SELECT "+s.nextval).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("failed to advance sequence: %w", err)
	}
	return seq, nil
}

// Watermark implements the [diff.Store] interface. It returns the highest
// sequence value assigned so far, or 0 if the sequence was never advanced.
func (s *Store) Watermark(ctx context.Context, tx *sql.Tx) (int64, error) {
	query := "SELECT CASE WHEN is_called THEN last_value" +
		" ELSE last_value - 1 END FROM " + s.sequence
	var seq int64
	if err := tx.QueryRowContext(ctx, query).Scan(&seq); err != nil {
		return 0, fmt.Errorf("failed to read sequence watermark: %w", err)
	}
	return seq, nil
}

// Claim implements the [diff.Store] interface. It records the given
// mutation IDs and returns the subset that was not seen before.
func (s *Store) Claim(
	ctx context.Context,
	tx *sql.Tx,
	userID uuid.UUID,
	ids []uuid.UUID,
) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	query := "INSERT INTO " + s.mutations + " (id, user_id)" +
		" SELECT unnest($1::uuid[]), $2::uuid" +
		" ON CONFLICT (id) DO NOTHING RETURNING id"

	rows, err := tx.QueryContext(ctx, query, ids, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to claim mutations: %w", err)
	}
	defer close(rows, s.logger)

	var claimed []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan claimed mutation: %w", err)
		}
		claimed = append(claimed, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read claimed mutations: %w", err)
	}
	return claimed, nil
}

// Grants implements the [diff.Store] interface. It returns, for each of
// the given owners, the identifiers of the teams currently granted access
// to their personal documents. Owners without live grants are omitted.
func (s *Store) Grants(
	ctx context.Context,
	tx *sql.Tx,
	owners []uuid.UUID,
) (map[uuid.UUID][]uuid.UUID, error) {
	out := make(map[uuid.UUID][]uuid.UUID, len(owners))
	if len(owners) == 0 {
		return out, nil
	}

	query := "SELECT user_id, team_id FROM " + s.shares +
		" WHERE user_id = ANY($1::uuid[])"
	rows, err := tx.QueryContext(ctx, query, owners)
	if err != nil {
		return nil, fmt.Errorf("failed to read grants: %w", err)
	}
	defer close(rows, s.logger)

	for rows.Next() {
		var owner, team uuid.UUID
		if err := rows.Scan(&owner, &team); err != nil {
			return nil, fmt.Errorf("failed to scan grant: %w", err)
		}
		out[owner] = append(out[owner], team)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read grants: %w", err)
	}
	return out, nil
}

// Touch re-sequences all personal documents (and their descendants) of the
// given owner across every registered table so they re-enter the patch
// feed. The built-in [Store.Shares] handler invokes it whenever a grant
// lands; backend flows may call it to re-feed an owner's personal documents
// to newly granted teams. Callers must hold the owner's scope locks (see
// [Store.Mutate]).
func (s *Store) Touch(
	ctx context.Context,
	tx *sql.Tx,
	ownerID uuid.UUID,
) error {
	for _, t := range s.order {
		query := "UPDATE " + t.ident + " SET seq = " + s.nextval +
			" WHERE " + t.userCol + " = $1::uuid" +
			" AND " + t.teamCol + " IS NULL"
		if _, err := tx.ExecContext(ctx, query, ownerID); err != nil {
			return fmt.Errorf("failed to touch table %q: %w", t.name, err)
		}
	}
	return nil
}

// Mutate runs fn within a single transaction after acquiring the exclusive
// advisory locks of the given scope (its user and all its teams).
//
// IMPORTANT: Every backend-initiated write to synced tables MUST go through
// Mutate (or acquire the equivalent locks via [Store.Lock]). Writing to a
// synced table without holding the scope locks races against concurrent
// sync transactions and can assign sequence values that a client's feed
// scan silently skips, permanently desynchronizing that client.
//
// A compliant backend write stamps the rows with a fresh engine timestamp
// and re-enters them into the patch feed via [Table.Reseq]; backend
// deletions go through [Table.Bury]:
//
//	now := engine.Now()
//	err := store.Mutate(ctx, scope, func(ctx context.Context, tx *sql.Tx) error
//
//	{
//		    if _, err := tx.ExecContext(ctx,
//		        "UPDATE assets SET data = $2, hlc = $3 WHERE id = $1",
//		        id, data, int64(now),
//		    ); err != nil {
//		        return err
//		    }
//		    return assets.Reseq(ctx, tx, []uuid.UUID{id})
//		})
//
// Flows inserting rows directly may instead allocate sequence values
// themselves: [Store.Barrier] doubles as a seq allocator, returning one
// fresh feed sequence value per call.
func (s *Store) Mutate(
	ctx context.Context,
	scope diff.Scope,
	fn func(ctx context.Context, tx *sql.Tx) error,
) error {
	return s.Exec(ctx, func(ctx context.Context, tx *sql.Tx) error {
		keys := make([]uuid.UUID, 0, len(scope.Teams)+1)
		keys = append(keys, scope.UserID)
		keys = append(keys, scope.Teams...)

		// Personal documents of the acting user may be visible to teams
		// through live grants; those teams' members read under a shared
		// lock on the team key, so a backend write must hold it exclusively
		// too. This mirrors the engine's fence (see Engine.assemble).
		grants, err := s.Grants(ctx, tx, []uuid.UUID{scope.UserID})
		if err != nil {
			return err
		}
		keys = append(keys, grants[scope.UserID]...)

		if err := s.Lock(ctx, tx, nil, keys); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}

// errDrift signals that the grant set changed between its snapshot and the
// lock acquisition and the offboarding transaction must be retried.
var errDrift = errors.New("grant set drifted")

// OffboardTeam buries every share that grants the given team access to
// owners' personal documents. Each grant is removed and tombstoned so the
// team's members receive a share deletion on their next sync and their
// clients purge the shared documents (see the client contract). It returns
// the number of grants buried.
//
// OffboardTeam is safe against concurrent grant writes: it locks the team
// key and every granting owner in one batch, re-verifies the grant set
// under the locks, and retries once when a grant landed in between. If the
// set drifts again, it returns an error wrapping [diff.ErrConflict]; the
// condition is transient, and the call can simply be repeated.
//
// Call it before deleting a team row: document_shares references teams with
// ON DELETE RESTRICT precisely so a team cannot be dropped while grants —
// and the deletions its members are owed — still reference it. Stamp the
// tombstones with a fresh timestamp from the engine clock ([Engine.Now]).
//
// Team removal is therefore a lifecycle, not an instant: after offboarding,
// the grant tombstones themselves reference the team (so its members can
// still fetch the deletions), and the RESTRICT on document_tombstones keeps
// the team row alive until those tombstones age out and are pruned with
// [Store.PruneTombstones]. Only then is the team row deletable.
//
// It does not touch documents assigned directly to the team (team_id equal
// to teamID); reassigning or deleting those is an application decision,
// carried out through the normal sync handlers before the team is removed.
func (s *Store) OffboardTeam(
	ctx context.Context,
	teamID uuid.UUID,
	at hlc.Time,
) (int64, error) {
	var buried int64

	// Owner keys accumulate across attempts, mirroring the engine's
	// resolve/lock/verify pattern: all advisory locks must be taken in one
	// sorted batch (incremental acquisition would break the global lock
	// order and risk deadlock), so a grant landing between the snapshot and
	// the lock forces a retry with the union of both lock sets.
	owners := make(map[uuid.UUID]struct{})
	for attempt := 0; ; attempt++ {
		err := s.Exec(ctx, func(ctx context.Context, tx *sql.Tx) error {
			// Seed the lock set from an unlocked snapshot on the first
			// attempt; later attempts already carry the drifted set.
			if attempt == 0 {
				seed, err := s.grantOwners(ctx, tx, teamID)
				if err != nil {
					return err
				}
				for _, owner := range seed {
					owners[owner] = struct{}{}
				}
			}

			// Every owner that granted this team access appears in a
			// tombstone and has their grant visibility reset, so the lock
			// set is the team key (whose members read the tombstones under
			// a shared lock) plus each granting owner (whose own feed
			// serves the share row).
			keys := make([]uuid.UUID, 0, len(owners)+1)
			keys = append(keys, teamID)
			for owner := range owners {
				keys = append(keys, owner)
			}
			if err := s.Lock(ctx, tx, nil, keys); err != nil {
				return err
			}

			// Re-verify under the locks: holding the team key exclusively
			// blocks any further grant for this team (share writes fence on
			// the team key), so a snapshot that matches the held set is
			// final. Any owner that slipped in between joins the next
			// attempt's lock set.
			current, err := s.grantOwners(ctx, tx, teamID)
			if err != nil {
				return err
			}
			drifted := false
			for _, owner := range current {
				if _, held := owners[owner]; !held {
					owners[owner] = struct{}{}
					drifted = true
				}
			}
			if drifted {
				return errDrift
			}

			return s.buryGrants(ctx, tx, teamID, at, &buried)
		})
		if errors.Is(err, errDrift) && attempt == 0 {
			continue
		}
		if errors.Is(err, errDrift) {
			return 0, fmt.Errorf("offboard team: %w", diff.ErrConflict)
		}
		return buried, err
	}
}

// grantOwners returns the owners currently granting the given team access
// to their personal documents.
func (s *Store) grantOwners(
	ctx context.Context,
	tx *sql.Tx,
	teamID uuid.UUID,
) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT user_id FROM "+s.shares+
			" WHERE team_id = $1::uuid", teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to list team grants: %w", err)
	}
	defer close(rows, s.logger)

	var owners []uuid.UUID
	for rows.Next() {
		var owner uuid.UUID
		if err := rows.Scan(&owner); err != nil {
			return nil, fmt.Errorf("failed to scan grant owner: %w", err)
		}
		owners = append(owners, owner)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list team grants: %w", err)
	}
	return owners, nil
}

// buryGrants removes and tombstones every grant of the given team, storing
// the number of buried grants in buried. Callers must hold the team key and
// every granting owner's key exclusively.
func (s *Store) buryGrants(
	ctx context.Context,
	tx *sql.Tx,
	teamID uuid.UUID,
	at hlc.Time,
	buried *int64,
) error {
	query := "WITH removed AS (" +
		" DELETE FROM " + s.shares + " WHERE team_id = $1::uuid" +
		" RETURNING id, user_id, team_id" +
		") INSERT INTO " + s.tombstones + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $2::text, id, user_id, team_id, $3, " + s.nextval +
		" FROM removed" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc"
	res, err := tx.ExecContext(ctx, query,
		teamID, diff.ModelShare, int64(at))
	if err != nil {
		return fmt.Errorf("failed to bury team grants: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to count buried grants: %w", err)
	}
	*buried = n
	return nil
}

// PruneMutations deletes mutation records older than the given age and
// returns the number of rows removed. Run it periodically; the retention
// period bounds the window during which replayed mutations deduplicate.
func (s *Store) PruneMutations(
	ctx context.Context,
	olderThan time.Duration,
) (int64, error) {
	query := "DELETE FROM " + s.mutations +
		" WHERE applied_at < now() - make_interval(secs => $1)"
	res, err := s.db.ExecContext(ctx, query, olderThan.Seconds())
	if err != nil {
		return 0, fmt.Errorf("failed to prune mutations: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to count pruned mutations: %w", err)
	}
	return n, nil
}

// PruneTombstones deletes tombstones older than the given age, advances the
// retention floor past the highest pruned sequence value, and returns the
// number of rows removed. Clients whose cursor predates the new floor are
// forced into a full resync.
func (s *Store) PruneTombstones(
	ctx context.Context,
	olderThan time.Duration,
) (int64, error) {
	var pruned int64
	err := s.Exec(ctx, func(ctx context.Context, tx *sql.Tx) error {
		query := "WITH pruned AS (DELETE FROM " + s.tombstones +
			" WHERE deleted_at < now() - make_interval(secs => $1)" +
			" RETURNING seq)" +
			" SELECT count(*), coalesce(max(seq), 0) FROM pruned"

		var peak int64
		err := tx.QueryRowContext(ctx, query, olderThan.Seconds()).
			Scan(&pruned, &peak)
		if err != nil {
			return fmt.Errorf("failed to prune tombstones: %w", err)
		}
		if pruned == 0 {
			return nil
		}

		query = "UPDATE " + s.state +
			" SET seq = GREATEST(seq, $1) WHERE key = 'floor'"
		if _, err := tx.ExecContext(ctx, query, peak); err != nil {
			return fmt.Errorf("failed to advance retention floor: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return pruned, nil
}

// Shares returns the built-in handler for the reserved "share" model,
// backed by the share grants table. Register it via
// [diff.Registry.RegisterShares].
func (s *Store) Shares() diff.Handler[*sql.Tx] {
	return &shares{store: s}
}

// shares implements [diff.Handler] for the reserved "share" model. A share
// is a root document {id, user_id, team_id} granting a team access to the
// owner's personal documents; at most one live grant exists per (user_id,
// team_id) pair.
type shares struct {
	store *Store
}

// Upsert implements the [diff.Handler] interface with row-level
// last-write-wins. Only the owner of a grant may mutate it. A newer grant
// for an already granted (user, team) pair supersedes the older duplicate:
// the duplicate is removed and tombstoned so clients converge on a single
// grant row. When a grant's team changes, the previously granted team
// receives a move tombstone carrying the old identity, and whenever a grant
// lands (its insert or update was actually applied), the owner's personal
// documents are re-fed to the granted teams via [Store.Touch].
func (h *shares) Upsert(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	if len(ops) == 0 {
		return nil
	}
	s := h.store

	// Fold intra-batch duplicates for the same (user, team) pair: only the
	// newest grant per pair is applied, the losers are tombstoned under the
	// winner's timestamp, exactly as if they had landed first and been
	// superseded in a later request.
	type pair struct{ user, team uuid.UUID }
	best := make(map[pair]diff.Op, len(ops))
	for _, op := range ops {
		if op.Meta.TeamID == uuid.Nil() {
			return errors.New("share is missing team_id")
		}
		k := pair{user: op.Meta.UserID, team: op.Meta.TeamID}
		cur, exists := best[k]
		if !exists || op.Time > cur.Time || (op.Time == cur.Time &&
			op.Meta.ID.Compare(cur.Meta.ID) > 0) {
			best[k] = op
		}
	}
	var wins []diff.Op
	var losers []move
	for _, op := range ops {
		w := best[pair{user: op.Meta.UserID, team: op.Meta.TeamID}]
		if w.Meta.ID == op.Meta.ID {
			wins = append(wins, op)
		} else {
			losers = append(losers, move{
				id:   op.Meta.ID,
				user: op.Meta.UserID,
				team: op.Meta.TeamID,
				hlc:  int64(w.Time),
			})
		}
	}

	n := len(wins)
	ids := make([]uuid.UUID, n)
	users := make([]uuid.UUID, n)
	teams := make([]uuid.UUID, n)
	hlcs := make([]int64, n)
	for i, op := range wins {
		ids[i] = op.Meta.ID
		users[i] = op.Meta.UserID
		teams[i] = op.Meta.TeamID
		hlcs[i] = int64(op.Time)
	}

	// Snapshot the current team assignments so team moves can be detected
	// after the upsert.
	before, err := h.snapshot(ctx, tx, ids)
	if err != nil {
		return err
	}

	// Remove older duplicate grants for the same (user, team) pair and
	// tombstone them under the incoming timestamp. This runs as its own
	// statement so the upsert's duplicate check below observes the
	// post-supersede state.
	supersede := "WITH incoming AS (" +
		" SELECT t.id, t.user_id, t.team_id, t.hlc" +
		" FROM unnest($1::uuid[], $2::uuid[], $3::uuid[], $4::bigint[])" +
		" AS t(id, user_id, team_id, hlc)" +
		"), stale AS (" +
		" DELETE FROM " + s.shares + " s USING incoming i" +
		" WHERE s.user_id = i.user_id AND s.team_id = i.team_id" +
		" AND s.id <> i.id AND s.hlc < i.hlc" +
		" AND s.user_id = $5::uuid" +
		" RETURNING s.id, s.user_id, s.team_id, i.hlc" +
		") INSERT INTO " + s.tombstones + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $6::text, id, user_id, team_id, hlc, " + s.nextval +
		" FROM stale" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc"

	// Last-write-wins upsert honoring tombstones. A tombstone may only be
	// bypassed (resurrection) when its identity lies within the caller's
	// scope or the grant is still alive; clearing it additionally requires
	// the grant to be dead, so departure tombstones of live grants survive
	// for late syncers. The whole operation is suppressed while a surviving
	// duplicate grant still holds the (user, team) pair, and the conflict
	// update only applies when the caller owns the existing row.
	upsert := "WITH incoming AS (" +
		" SELECT t.id, t.user_id, t.team_id, t.hlc" +
		" FROM unnest($1::uuid[], $2::uuid[], $3::uuid[], $4::bigint[])" +
		" AS t(id, user_id, team_id, hlc)" +
		"), alive AS (" +
		" SELECT i.* FROM incoming i" +
		" LEFT JOIN " + s.tombstones + " ts" +
		" ON ts.type = $6::text AND ts.id = i.id" +
		" LEFT JOIN " + s.shares + " r ON r.id = i.id" +
		" WHERE (ts.id IS NULL OR (i.hlc > ts.hlc" +
		" AND (r.id IS NOT NULL" +
		" OR ts.user_id = $5::uuid OR ts.team_id = ANY($7::uuid[]))))" +
		" AND NOT EXISTS (" +
		" SELECT 1 FROM " + s.shares + " x" +
		" WHERE x.user_id = i.user_id AND x.team_id = i.team_id" +
		" AND x.id <> i.id" +
		")" +
		"), cleared AS (" +
		" DELETE FROM " + s.tombstones + " ts USING alive a" +
		" WHERE ts.type = $6::text AND ts.id = a.id" +
		" AND (ts.user_id = $5::uuid OR ts.team_id = ANY($7::uuid[]))" +
		" AND NOT EXISTS (" +
		" SELECT 1 FROM " + s.shares + " r WHERE r.id = a.id" +
		")" +
		") INSERT INTO " + s.shares + " AS s" +
		" (id, user_id, team_id, hlc, seq)" +
		" SELECT a.id, a.user_id, a.team_id, a.hlc, " + s.nextval +
		" FROM alive a" +
		" ON CONFLICT (id) DO UPDATE SET" +
		" team_id = EXCLUDED.team_id, hlc = EXCLUDED.hlc," +
		" seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > s.hlc AND s.user_id = $5::uuid" +
		" RETURNING s.id, s.user_id, s.team_id, s.hlc"

	if _, err := tx.ExecContext(ctx, supersede,
		ids, users, teams, hlcs, scope.UserID, diff.ModelShare,
	); err != nil {
		return fmt.Errorf("failed to supersede duplicate shares: %w", err)
	}

	rows, err := tx.QueryContext(ctx, upsert,
		ids, users, teams, hlcs, scope.UserID, diff.ModelShare, scope.Teams,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert shares: %w", err)
	}
	landed, err := stamps(rows, s.logger)
	if err != nil {
		return err
	}

	// The old team of a moved grant must receive the grant's removal: write
	// a move tombstone carrying the grant's previous identity.
	moves := slices.Clone(losers)
	for _, l := range landed {
		old, existed := before[l.id]
		if existed && old != l.team {
			moves = append(moves, move{
				id:   l.id,
				user: l.user,
				team: old, // never zero: team_id is NOT NULL
				hlc:  l.hlc,
			})
		}
	}
	if err := s.entomb(ctx, tx, diff.ModelShare, moves); err != nil {
		return err
	}

	// A grant re-feeds the owner's personal documents only when it genuinely
	// WIDENS visibility — a brand-new grant id (a fresh insert) or a grant
	// whose team changed (a move exposing a NEW team). A landed grant that
	// merely refreshed an existing (id, team) pair under a newer timestamp
	// grants no new audience, so the full owner-wide re-seq of Touch would
	// be pure write amplification, re-delivering every personal document to
	// teams that already had it. Skip it in that case.
	//
	// This never under-touches: any team newly gaining access does so via a
	// fresh grant id or a team change, both caught below. (Superseding a
	// duplicate grant under a new id still touches — the pair was already
	// visible, so this over-touches, but it is safe.)
	if len(landed) > 0 {
		for _, l := range landed {
			old, existed := before[l.id]
			if !existed || old != l.team {
				return s.Touch(ctx, tx, scope.UserID)
			}
		}
	}
	return nil
}

// snapshot returns the current team assignment of the given grants.
func (h *shares) snapshot(
	ctx context.Context,
	tx *sql.Tx,
	ids []uuid.UUID,
) (map[uuid.UUID]uuid.UUID, error) {
	s := h.store
	query := "SELECT id, team_id FROM " + s.shares +
		" WHERE id = ANY($1::uuid[])"
	rows, err := tx.QueryContext(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to snapshot shares: %w", err)
	}
	states, err := scanStates(rows, s.logger)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]uuid.UUID, len(states))
	for _, st := range states {
		out[st.id] = st.team
	}
	return out, nil
}

// Delete implements the [diff.Handler] interface. Only the owner of a grant
// may revoke it; stale deletes are skipped, and deletes of absent grants
// tombstone the payload identity.
func (h *shares) Delete(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	if len(ops) == 0 {
		return nil
	}
	s := h.store

	n := len(ops)
	ids := make([]uuid.UUID, n)
	hlcs := make([]int64, n)
	users := make([]uuid.UUID, n)
	teams := make([]uuid.UUID, n)
	for i, op := range ops {
		ids[i] = op.Meta.ID
		hlcs[i] = int64(op.Time)
		users[i] = op.Meta.UserID
		teams[i] = op.Meta.TeamID
	}

	query := "WITH incoming AS (" +
		" SELECT t.id, t.hlc, t.user_id," +
		" nullif(t.team_id, " + zeroUUID + ") AS team_id" +
		" FROM unnest($1::uuid[], $2::bigint[], $3::uuid[], $4::uuid[])" +
		" AS t(id, hlc, user_id, team_id)" +
		"), victims AS (" +
		" DELETE FROM " + s.shares + " s USING incoming i" +
		" WHERE s.id = i.id AND s.hlc < i.hlc AND s.user_id = $5::uuid" +
		" RETURNING s.id, s.user_id, s.team_id, i.hlc" +
		"), scoped AS (" +
		" SELECT id, user_id, team_id, hlc FROM victims" +
		" UNION ALL" +
		" SELECT i.id, i.user_id, i.team_id, i.hlc FROM incoming i" +
		" WHERE NOT EXISTS (" +
		" SELECT 1 FROM " + s.shares + " s WHERE s.id = i.id" +
		")" +
		") INSERT INTO " + s.tombstones + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $6::text, id, user_id, team_id, hlc, " + s.nextval +
		" FROM scoped" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc"

	if _, err := tx.ExecContext(
		ctx,
		query,
		ids,
		hlcs,
		users,
		teams,
		scope.UserID,
		diff.ModelShare,
	); err != nil {
		return fmt.Errorf("failed to delete shares: %w", err)
	}
	return nil
}

// Fetch implements the [diff.Handler] interface. Grants are visible to
// their owner and to members of the granted team; payloads are
// reconstructed from the row columns.
//
// The team-visibility branch is expanded into ONE indexable arm per team
// (team_id = $k rather than team_id = ANY($teams)), so each arm streams
// from the (team_id, seq) index already in sequence order and the planner
// can MergeAppend the arms under ORDER BY seq LIMIT and stop early, instead
// of sorting the whole window on every page. Team counts are small, so the
// query shape (rebuilt per call from the team count) stays cheap.
//
// Parameter layout: $1 user, $2 since, $3 until, $4 model, $5 limit, and
// $6.. the individual team keys.
func (h *shares) Fetch(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	w diff.Window,
) ([]diff.Version, error) {
	s := h.store
	n := len(scope.Teams)

	data := "jsonb_build_object(" +
		"'id', id, 'user_id', user_id, 'team_id', team_id" +
		") AS data"
	live := func(cond string) string {
		return "SELECT id, seq, hlc, FALSE AS deleted, " + data +
			" FROM " + s.shares +
			" WHERE " + cond + " AND seq > $2 AND seq < $3"
	}
	dead := func(cond string) string {
		return "SELECT id, seq, hlc, TRUE, NULL::jsonb" +
			" FROM " + s.tombstones +
			" WHERE type = $4::text AND " + cond +
			" AND seq > $2 AND seq < $3"
	}

	var b strings.Builder
	b.WriteString("(")
	b.WriteString(live("user_id = $1::uuid"))
	for i := range n {
		p := "$" + strconv.Itoa(6+i)
		b.WriteString(" UNION ALL " +
			live("team_id = "+p+"::uuid AND user_id <> $1::uuid"))
	}
	b.WriteString(" UNION ALL " + dead("user_id = $1::uuid"))
	for i := range n {
		p := "$" + strconv.Itoa(6+i)
		b.WriteString(" UNION ALL " +
			dead("team_id = "+p+"::uuid AND user_id <> $1::uuid"))
	}
	b.WriteString(") ORDER BY seq LIMIT $5")

	args := make([]any, 0, 5+n)
	args = append(
		args,
		scope.UserID,
		w.Since,
		w.Until,
		diff.ModelShare,
		w.Limit,
	)
	for _, team := range scope.Teams {
		args = append(args, team)
	}
	rows, err := tx.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch shares: %w", err)
	}
	return collect(rows, s.logger)
}

// Read implements the [diff.Reader] interface. A grant is visible to its
// owner and to members of the granted team; the payload is reconstructed
// from the row columns, like in [shares.Fetch].
func (h *shares) Read(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	id uuid.UUID,
) (diff.Version, bool, error) {
	s := h.store
	query := "SELECT seq, hlc, jsonb_build_object(" +
		"'id', id, 'user_id', user_id, 'team_id', team_id)" +
		" FROM " + s.shares + " WHERE id = $1::uuid" +
		" AND (user_id = $2::uuid OR team_id = ANY($3::uuid[]))"

	v := diff.Version{ID: id}
	var ts int64
	var data []byte
	err := tx.QueryRowContext(ctx, query,
		id, scope.UserID, scope.Teams,
	).Scan(&v.Seq, &ts, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return diff.Version{}, false, nil
	}
	if err != nil {
		return diff.Version{}, false, fmt.Errorf(
			"failed to read share: %w", err,
		)
	}
	v.Time = hlc.Time(ts)
	v.Data = jsontext.Value(data)
	return v, true, nil
}

// Resolve implements the [diff.Handler] interface.
func (h *shares) Resolve(
	ctx context.Context,
	tx *sql.Tx,
	ids []uuid.UUID,
) (map[uuid.UUID]diff.Meta, error) {
	s := h.store
	query := "SELECT id, user_id, team_id FROM " +
		s.shares + " WHERE id = ANY($1::uuid[])"
	return resolve(ctx, tx, query, ids, s.logger)
}

// move is one departed-audience tombstone entry: the identity a document
// carried before it moved (or, for superseded grants, before it was
// replaced), together with the timestamp of the displacing write.
type move struct {
	id   uuid.UUID
	user uuid.UUID
	team uuid.UUID // zero for personal documents
	hlc  int64
}

// entomb records move tombstones for the given model: each entry buries the
// document's previous identity under the displacing timestamp and a fresh
// sequence value, so the departed audience receives a deletion. Members of
// the new audience that see the corresponding update in the same page keep
// the document (equal-time updates beat deletions in the client contract).
func (s *Store) entomb(
	ctx context.Context,
	tx *sql.Tx,
	model string,
	moves []move,
) error {
	if len(moves) == 0 {
		return nil
	}

	n := len(moves)
	ids := make([]uuid.UUID, n)
	users := make([]uuid.UUID, n)
	teams := make([]uuid.UUID, n)
	hlcs := make([]int64, n)
	for i, m := range moves {
		ids[i] = m.id
		users[i] = m.user
		teams[i] = m.team
		hlcs[i] = m.hlc
	}

	query := "INSERT INTO " + s.tombstones + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $1::text, m.id, m.user_id," +
		" nullif(m.team_id, " + zeroUUID + ")," +
		" m.hlc, " + s.nextval +
		" FROM unnest($2::uuid[], $3::uuid[], $4::uuid[], $5::bigint[])" +
		" AS m(id, user_id, team_id, hlc)" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" user_id = EXCLUDED.user_id, team_id = EXCLUDED.team_id," +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc"

	if _, err := tx.ExecContext(ctx, query,
		model, ids, users, teams, hlcs,
	); err != nil {
		return fmt.Errorf("failed to record move tombstones: %w", err)
	}
	return nil
}

// stamp is one written row as reported by a RETURNING clause: its
// post-write identity and timestamp. A zero team denotes a personal
// document (NULL team column).
type stamp struct {
	id   uuid.UUID
	user uuid.UUID
	team uuid.UUID
	hlc  int64
}

// stamps consumes rows of the shape (id, user_id, team_id, hlc).
func stamps(rows *sql.Rows, logger *slog.Logger) ([]stamp, error) {
	defer close(rows, logger)

	var out []stamp
	for rows.Next() {
		var st stamp
		if err := rows.Scan(&st.id, &st.user, &st.team, &st.hlc); err != nil {
			return nil, fmt.Errorf("failed to scan written document: %w", err)
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read written documents: %w", err)
	}
	return out, nil
}

// collect scans feed rows of the shape (id, seq, hlc, deleted, data) into
// versions, preserving row order.
func collect(rows *sql.Rows, logger *slog.Logger) ([]diff.Version, error) {
	defer close(rows, logger)

	var out []diff.Version
	for rows.Next() {
		var (
			id      uuid.UUID
			seq     int64
			ts      int64
			deleted bool
			data    []byte
		)
		if err := rows.Scan(&id, &seq, &ts, &deleted, &data); err != nil {
			return nil, fmt.Errorf("failed to scan feed row: %w", err)
		}
		v := diff.Version{
			ID:      id,
			Seq:     seq,
			Time:    hlc.Time(ts),
			Deleted: deleted,
		}
		if !deleted {
			v.Data = jsontext.Value(data)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read feed rows: %w", err)
	}
	return out, nil
}

// resolve executes an identity lookup of the shape (id, user_id, team_id)
// and assembles the resulting envelopes keyed by document ID.
func resolve(
	ctx context.Context,
	tx *sql.Tx,
	query string,
	ids []uuid.UUID,
	logger *slog.Logger,
) (map[uuid.UUID]diff.Meta, error) {
	out := make(map[uuid.UUID]diff.Meta, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	rows, err := tx.QueryContext(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve documents: %w", err)
	}
	defer close(rows, logger)

	for rows.Next() {
		var id, user, team uuid.UUID
		if err := rows.Scan(&id, &user, &team); err != nil {
			return nil, fmt.Errorf("failed to scan document identity: %w", err)
		}
		out[id] = diff.Meta{ID: id, UserID: user, TeamID: team}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read document identities: %w", err)
	}
	return out, nil
}

// close closes a result set, logging failures instead of shadowing the
// caller's error.
func close(rows *sql.Rows, logger *slog.Logger) {
	if err := rows.Close(); err != nil {
		logger.Error("Failed to close rows", log.Err(err))
	}
}

var (
	_ diff.Store[*sql.Tx]   = (*Store)(nil)
	_ diff.Handler[*sql.Tx] = (*shares)(nil)
	_ diff.Reader[*sql.Tx]  = (*shares)(nil)
)
