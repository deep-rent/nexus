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

// Package postgres provides the PostgreSQL reference driver for the diff
// synchronization engine.
//
// The [Store] implements the shared transactional machinery of
// [diff.Store]: sequencing, advisory locking, mutation deduplication, and
// tombstone retention. Entity types are backed by declarative [Table]
// handlers created with [NewTable], and the reserved "share" type is served
// by the built-in [Store.Shares] handler.
//
// # Usage
//
// Initialize the store with an existing [*sql.DB] connection, create its
// bookkeeping objects, and register one table per entity type.
//
// Example:
//
//	store := postgres.New(db)
//	if err := store.Init(ctx); err != nil {
//	    return err
//	}
//
//	assets := postgres.NewTable(store, "asset", "assets")
//	files := postgres.NewTable(store, "file", "files",
//	    postgres.WithParent("assets", "asset_id"))
//
//	reg := diff.NewRegistry[*sql.Tx]()
//	reg.Register[Asset]("asset", assets, diff.WithRootMeta())
//	reg.Register[File]("file", files, diff.WithOwner("asset", "asset_id"))
//	reg.RegisterShares(store.Shares())
//
//	engine := diff.New(store, reg)
//
// Applications managing their schema through the migrate package feed the
// embedded migration files returned by [Migrations] through their pipeline
// instead of calling [Store.Init].
package postgres

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/internal/pointer"
	"github.com/deep-rent/nexus/internal/quote"
	"github.com/deep-rent/nexus/internal/schema"
)

// Default names for the store's bookkeeping objects.
const (
	// DefaultSchema is the default PostgreSQL schema.
	DefaultSchema = "public"
	// DefaultMutationsTable is the default name of the mutation
	// deduplication table.
	DefaultMutationsTable = "diff_mutations"
	// DefaultTombstonesTable is the default name of the tombstone table.
	DefaultTombstonesTable = "diff_tombstones"
	// DefaultStateTable is the default name of the state table holding the
	// retention floor.
	DefaultStateTable = "diff_state"
	// DefaultSharesTable is the default name of the share grants table.
	DefaultSharesTable = "diff_shares"
	// DefaultSequence is the default name of the global feed sequence.
	DefaultSequence = "diff_seq"
)

// migrations embeds the SQL migration files creating the store's
// bookkeeping objects under their default names.
//
//go:embed migrations/*.sql
var migrations embed.FS

// Migrations returns the embedded SQL migration files creating the store's
// bookkeeping objects. The files follow the naming convention of the
// migrate/source/file package and use the default object names in the
// default schema.
//
// Feed them through a migrate pipeline instead of calling [Store.Init] when
// schema changes are managed through migrations:
//
//	m := migrate.New(
//	    migrate.WithSource(file.New(postgres.Migrations())),
//	    migrate.WithDriver(driver.New(db)),
//	)
//	err := m.Up(ctx)
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err) // unreachable: the embedded directory always exists
	}
	return sub
}

// config holds the internal configuration options for the PostgreSQL store.
type config struct {
	// schema is the PostgreSQL schema containing the bookkeeping objects.
	schema string
	// mutations is the name of the mutation deduplication table.
	mutations string
	// tombstones is the name of the tombstone table.
	tombstones string
	// state is the name of the state table.
	state string
	// shares is the name of the share grants table.
	shares string
	// sequence is the name of the global feed sequence.
	sequence string
	// logger is the structured logger for store activity.
	logger *slog.Logger
}

// Option configures a PostgreSQL [Store] instance.
type Option func(*config)

// WithSchema sets a custom database schema for the bookkeeping objects.
//
// Customized names are not covered by the embedded [Migrations]; the caller
// must create the objects themselves and [Store.Init] returns an error.
//
// Empty string values are ignored.
func WithSchema(name string) Option {
	return func(c *config) {
		if name != "" {
			c.schema = name
		}
	}
}

// WithMutationsTable sets a custom name for the mutation deduplication
// table.
//
// Customized names are not covered by the embedded [Migrations]; the caller
// must create the objects themselves and [Store.Init] returns an error.
//
// Empty string values are ignored.
func WithMutationsTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.mutations = name
		}
	}
}

// WithTombstonesTable sets a custom name for the tombstone table.
//
// Customized names are not covered by the embedded [Migrations]; the caller
// must create the objects themselves and [Store.Init] returns an error.
//
// Empty string values are ignored.
func WithTombstonesTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.tombstones = name
		}
	}
}

// WithStateTable sets a custom name for the state table.
//
// Customized names are not covered by the embedded [Migrations]; the caller
// must create the objects themselves and [Store.Init] returns an error.
//
// Empty string values are ignored.
func WithStateTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.state = name
		}
	}
}

// WithSharesTable sets a custom name for the share grants table.
//
// Customized names are not covered by the embedded [Migrations]; the caller
// must create the objects themselves and [Store.Init] returns an error.
//
// Empty string values are ignored.
func WithSharesTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.shares = name
		}
	}
}

// WithSequence sets a custom name for the global feed sequence.
//
// Customized names are not covered by the embedded [Migrations]; the caller
// must create the objects themselves and [Store.Init] returns an error.
//
// Empty string values are ignored.
func WithSequence(name string) Option {
	return func(c *config) {
		if name != "" {
			c.sequence = name
		}
	}
}

// WithLogger injects a structured logger to record store operations.
//
// Nil values are ignored, falling back to [slog.Default].
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Store implements the [diff.Store] interface for PostgreSQL.
//
// It provides the shared transactional machinery of the sync engine and
// acts as the registration hub for the [Table] handlers of the individual
// entity types. Table registration via [NewTable] is not safe for
// concurrent use; register all tables during startup, before serving.
type Store struct {
	// db is the underlying database connection pool.
	db *sql.DB
	// schema is the unquoted default schema.
	schema string
	// mutations, tombstones, state, shares, and sequence are the unquoted
	// object names.
	mutations  string
	tombstones string
	state      string
	shares     string
	sequence   string
	// identMutations etc. are the precomputed, safely quoted identifiers.
	identMutations  string
	identTombstones string
	identState      string
	identShares     string
	identSequence   string
	// nextval is the precomputed nextval() expression of the feed sequence.
	nextval string
	// logger records store operations.
	logger *slog.Logger
	// tables indexes all registered tables by their table name.
	tables map[string]*Table
	// order lists the registered tables in registration order (parents
	// always precede their children).
	order []*Table
}

// New creates a new PostgreSQL sync store around the given connection pool
// and options. It panics if db is nil (programmer error).
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
		db:              db,
		schema:          cfg.schema,
		mutations:       cfg.mutations,
		tombstones:      cfg.tombstones,
		state:           cfg.state,
		shares:          cfg.shares,
		sequence:        cfg.sequence,
		identMutations:  ident(cfg.schema, cfg.mutations),
		identTombstones: ident(cfg.schema, cfg.tombstones),
		identState:      ident(cfg.schema, cfg.state),
		identShares:     ident(cfg.schema, cfg.shares),
		identSequence:   ident(cfg.schema, cfg.sequence),
		logger:          cfg.logger,
		tables:          make(map[string]*Table),
	}
	s.nextval = "nextval(" + literal(s.identSequence) + ")"

	return s
}

// Init ensures that all bookkeeping objects exist by executing the embedded
// up migration files (see [Migrations]) in ascending version order. All
// statements are idempotent, so Init may be called on every startup.
//
// The migration files are static and only cover the default object names in
// the default schema: when any custom name is configured, Init returns an
// error and the caller must manage the schema themselves, e.g. by feeding
// [Migrations] through a migrate pipeline against adjusted files.
func (s *Store) Init(ctx context.Context) error {
	if s.customized() {
		return errors.New(
			"init only supports the default object names;" +
				" custom names require caller-managed schema migrations",
		)
	}

	s.logger.Debug(
		"Initializing sync store objects if missing",
		slog.String("schema", s.schema),
	)

	scripts, err := upScripts()
	if err != nil {
		return err
	}
	for _, script := range scripts {
		for _, stmt := range schema.Postgres(script) {
			if _, err := s.db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("failed to initialize store: %w", err)
			}
		}
	}
	return nil
}

// customized reports whether any bookkeeping object name deviates from the
// defaults baked into the embedded migration files.
func (s *Store) customized() bool {
	return s.schema != DefaultSchema ||
		s.mutations != DefaultMutationsTable ||
		s.tombstones != DefaultTombstonesTable ||
		s.state != DefaultStateTable ||
		s.shares != DefaultSharesTable ||
		s.sequence != DefaultSequence
}

// upScripts returns the contents of the embedded up migration files, sorted
// by ascending version.
func upScripts() ([][]byte, error) {
	names, err := fs.Glob(migrations, "migrations/*.up.sql")
	if err != nil {
		return nil, fmt.Errorf("failed to list embedded migrations: %w", err)
	}

	type script struct {
		version uint64
		content []byte
	}
	scripts := make([]script, 0, len(names))
	for _, name := range names {
		raw, _, ok := strings.Cut(path.Base(name), "_")
		if !ok {
			return nil, fmt.Errorf("malformed migration filename %q", name)
		}
		version, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("malformed migration filename %q", name)
		}
		content, err := fs.ReadFile(migrations, name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration %q: %w", name, err)
		}
		scripts = append(scripts, script{version: version, content: content})
	}
	slices.SortFunc(scripts, func(a, b script) int {
		return cmp.Compare(a.version, b.version)
	})

	out := make([][]byte, len(scripts))
	for i, sc := range scripts {
		out[i] = sc.content
	}
	return out, nil
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
			s.logger.Error("Failed to rollback transaction", slog.Any("error", e))
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
// scoped advisory locks on the given keys, deduplicated and sorted in
// ascending order so concurrent callers never deadlock.
func (s *Store) Lock(ctx context.Context, tx *sql.Tx, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	locks := make([]int64, 0, len(keys))
	seen := make(map[int64]struct{}, len(keys))
	for _, key := range keys {
		k := lockKey(key)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		locks = append(locks, k)
	}
	slices.Sort(locks)

	for _, k := range locks {
		if _, err := tx.ExecContext(
			ctx,
			"SELECT pg_advisory_xact_lock($1)",
			k,
		); err != nil {
			return fmt.Errorf("failed to acquire advisory lock: %w", err)
		}
	}
	return nil
}

// lockKey derives a positive 64-bit advisory lock key from an opaque scope
// identifier.
func lockKey(key string) int64 {
	h := sha256.New()
	h.Write([]byte("diff:scope:"))
	h.Write([]byte(key))
	sum := h.Sum(nil)
	return int64(binary.BigEndian.Uint64(sum[:8]) & 0x7FFFFFFFFFFFFFFF)
}

// Floor implements the [diff.Store] interface. It returns the retention
// floor, or 0 if the state row is missing.
func (s *Store) Floor(ctx context.Context, tx *sql.Tx) (int64, error) {
	query := "SELECT seq FROM " + s.identState + " WHERE key = 'floor'"
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
		" ELSE last_value - 1 END FROM " + s.identSequence
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
	userID string,
	ids []uuid.UUID,
) ([]uuid.UUID, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	query := "INSERT INTO " + s.identMutations + " (id, user_id)" +
		" SELECT unnest($1::uuid[]), $2::uuid" +
		" ON CONFLICT (id) DO NOTHING RETURNING id::text"

	rows, err := tx.QueryContext(ctx, query, toStrings(ids), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to claim mutations: %w", err)
	}
	defer closeRows(rows, s.logger)

	var claimed []uuid.UUID
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("failed to scan claimed mutation: %w", err)
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse claimed mutation: %w", err)
		}
		claimed = append(claimed, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read claimed mutations: %w", err)
	}
	return claimed, nil
}

// Touch implements the [diff.Store] interface. It re-sequences all personal
// documents (and their descendants) of the given owner across every
// registered table so they re-enter the patch feed.
func (s *Store) Touch(
	ctx context.Context,
	tx *sql.Tx,
	ownerID string,
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

// Mutate runs fn within a single transaction after acquiring the advisory
// locks of the given scope (its user and all its teams).
//
// IMPORTANT: Every backend-initiated write to synced tables MUST go through
// Mutate (or acquire the equivalent locks via [Store.Lock]). Writing to a
// synced table without holding the scope locks races against concurrent
// sync transactions and can assign sequence values that a client's feed
// scan silently skips, permanently desynchronizing that client.
func (s *Store) Mutate(
	ctx context.Context,
	scope diff.Scope,
	fn func(ctx context.Context, tx *sql.Tx) error,
) error {
	return s.Exec(ctx, func(ctx context.Context, tx *sql.Tx) error {
		keys := make([]string, 0, len(scope.Teams)+1)
		keys = append(keys, scope.UserID)
		keys = append(keys, scope.Teams...)
		if err := s.Lock(ctx, tx, keys); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}

// PruneMutations deletes mutation records older than the given age and
// returns the number of rows removed. Run it periodically; the retention
// period bounds the window during which replayed mutations deduplicate.
func (s *Store) PruneMutations(
	ctx context.Context,
	olderThan time.Duration,
) (int64, error) {
	query := "DELETE FROM " + s.identMutations +
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
		query := "WITH pruned AS (DELETE FROM " + s.identTombstones +
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

		query = "UPDATE " + s.identState +
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

// Shares returns the built-in handler for the reserved "share" entity type,
// backed by the share grants table. Register it via
// [diff.Registry.RegisterShares].
func (s *Store) Shares() diff.Handler[*sql.Tx] {
	return &shares{store: s}
}

// shares implements [diff.Handler] for the reserved "share" entity type. A
// share is a root document {id, user_id, team_id} granting a team access to
// the owner's personal documents; at most one live grant exists per
// (user_id, team_id) pair.
type shares struct {
	store *Store
}

// Upsert implements the [diff.Handler] interface with row-level
// last-write-wins. Only the owner of a grant may mutate it. A newer grant
// for an already granted (user, team) pair supersedes the older duplicate:
// the duplicate is removed and tombstoned so clients converge on a single
// grant row.
func (h *shares) Upsert(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	ops []diff.Op,
) error {
	s := h.store

	// Remove older duplicate grants for the same (user, team) pair and
	// tombstone them under the incoming timestamp.
	supersede := "WITH stale AS (" +
		" DELETE FROM " + s.identShares + " s" +
		" WHERE s.user_id = $2::uuid AND s.team_id = $3::uuid" +
		" AND s.id <> $1::uuid AND s.hlc < $4::bigint" +
		" AND s.user_id = $5::uuid" +
		" RETURNING s.id, s.user_id, s.team_id" +
		") INSERT INTO " + s.identTombstones + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $6::text, id, user_id, team_id, $4::bigint, " + s.nextval +
		" FROM stale" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc"

	// Last-write-wins upsert honoring tombstones. The whole operation is
	// suppressed (including tombstone clearing) while a surviving duplicate
	// grant still holds the (user, team) pair, and the conflict update only
	// applies when the caller owns the existing row.
	upsert := "WITH incoming AS (" +
		" SELECT $1::uuid AS id, $2::uuid AS user_id," +
		" $3::uuid AS team_id, $4::bigint AS hlc" +
		"), alive AS (" +
		" SELECT i.* FROM incoming i" +
		" LEFT JOIN " + s.identTombstones + " ts" +
		" ON ts.type = $6::text AND ts.id = i.id" +
		" WHERE (ts.id IS NULL OR i.hlc > ts.hlc)" +
		" AND NOT EXISTS (" +
		" SELECT 1 FROM " + s.identShares + " x" +
		" WHERE x.user_id = i.user_id AND x.team_id = i.team_id" +
		" AND x.id <> i.id" +
		")" +
		"), cleared AS (" +
		" DELETE FROM " + s.identTombstones + " ts USING alive a" +
		" WHERE ts.type = $6::text AND ts.id = a.id" +
		") INSERT INTO " + s.identShares + " AS s" +
		" (id, user_id, team_id, hlc, seq)" +
		" SELECT a.id, a.user_id, a.team_id, a.hlc, " + s.nextval +
		" FROM alive a" +
		" ON CONFLICT (id) DO UPDATE SET" +
		" team_id = EXCLUDED.team_id, hlc = EXCLUDED.hlc," +
		" seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > s.hlc AND s.user_id = $5::uuid"

	for _, op := range ops {
		if op.Meta.TeamID == nil {
			return errors.New("share is missing team_id")
		}
		args := []any{
			op.Meta.ID.String(),
			op.Meta.UserID,
			*op.Meta.TeamID,
			int64(op.Time),
			scope.UserID,
			diff.TypeShare,
		}
		if _, err := tx.ExecContext(ctx, supersede, args...); err != nil {
			return fmt.Errorf("failed to supersede duplicate share: %w", err)
		}
		if _, err := tx.ExecContext(ctx, upsert, args...); err != nil {
			return fmt.Errorf("failed to upsert share: %w", err)
		}
	}
	return nil
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
	s := h.store

	query := "WITH incoming AS (" +
		" SELECT $1::uuid AS id, $2::bigint AS hlc, $3::uuid AS user_id," +
		" nullif($4, '')::uuid AS team_id" +
		"), victims AS (" +
		" DELETE FROM " + s.identShares + " s USING incoming i" +
		" WHERE s.id = i.id AND s.hlc < i.hlc AND s.user_id = $5::uuid" +
		" RETURNING s.id, s.user_id, s.team_id, i.hlc" +
		"), scoped AS (" +
		" SELECT id, user_id, team_id, hlc FROM victims" +
		" UNION ALL" +
		" SELECT i.id, i.user_id, i.team_id, i.hlc FROM incoming i" +
		" WHERE NOT EXISTS (" +
		" SELECT 1 FROM " + s.identShares + " s WHERE s.id = i.id" +
		")" +
		") INSERT INTO " + s.identTombstones + " AS ts" +
		" (type, id, user_id, team_id, hlc, seq)" +
		" SELECT $6::text, id, user_id, team_id, hlc, " + s.nextval +
		" FROM scoped" +
		" ON CONFLICT (type, id) DO UPDATE SET" +
		" hlc = EXCLUDED.hlc, seq = EXCLUDED.seq" +
		" WHERE EXCLUDED.hlc > ts.hlc"

	for _, op := range ops {
		args := []any{
			op.Meta.ID.String(),
			int64(op.Time),
			op.Meta.UserID,
			pointer.Value(op.Meta.TeamID),
			scope.UserID,
			diff.TypeShare,
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to delete share: %w", err)
		}
	}
	return nil
}

// Fetch implements the [diff.Handler] interface. Grants are visible to
// their owner and to members of the granted team; payloads are
// reconstructed from the row columns.
func (h *shares) Fetch(
	ctx context.Context,
	tx *sql.Tx,
	scope diff.Scope,
	w diff.Window,
) ([]diff.Version, error) {
	s := h.store

	query := "(SELECT id::text, seq, FALSE AS deleted," +
		" jsonb_build_object(" +
		"'id', id, 'user_id', user_id, 'team_id', team_id" +
		") AS data" +
		" FROM " + s.identShares +
		" WHERE (user_id = $1::uuid OR team_id = ANY($2::uuid[]))" +
		" AND seq > $3 AND seq < $4" +
		" UNION ALL" +
		" SELECT id::text, seq, TRUE AS deleted, NULL::jsonb AS data" +
		" FROM " + s.identTombstones +
		" WHERE type = $5::text" +
		" AND (user_id = $1::uuid OR team_id = ANY($2::uuid[]))" +
		" AND seq > $3 AND seq < $4" +
		") ORDER BY seq LIMIT $6"

	rows, err := tx.QueryContext(ctx, query,
		scope.UserID,
		scope.Teams,
		w.Since,
		w.Until,
		diff.TypeShare,
		w.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch shares: %w", err)
	}
	return collect(rows, s.logger)
}

// Resolve implements the [diff.Handler] interface.
func (h *shares) Resolve(
	ctx context.Context,
	tx *sql.Tx,
	ids []uuid.UUID,
) (map[uuid.UUID]diff.Meta, error) {
	s := h.store
	query := "SELECT id::text, user_id::text, team_id::text FROM " +
		s.identShares + " WHERE id = ANY($1::uuid[])"
	return resolve(ctx, tx, query, ids, s.logger)
}

// collect scans feed rows of the shape (id, seq, deleted, data) into
// versions, preserving row order.
func collect(rows *sql.Rows, logger *slog.Logger) ([]diff.Version, error) {
	defer closeRows(rows, logger)

	var out []diff.Version
	for rows.Next() {
		var (
			raw     string
			seq     int64
			deleted bool
			data    []byte
		)
		if err := rows.Scan(&raw, &seq, &deleted, &data); err != nil {
			return nil, fmt.Errorf("failed to scan feed row: %w", err)
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse document id: %w", err)
		}
		v := diff.Version{ID: id, Seq: seq, Deleted: deleted}
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

	rows, err := tx.QueryContext(ctx, query, toStrings(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve documents: %w", err)
	}
	defer closeRows(rows, logger)

	for rows.Next() {
		var rawID, user string
		var rawTeam sql.NullString
		if err := rows.Scan(&rawID, &user, &rawTeam); err != nil {
			return nil, fmt.Errorf("failed to scan document identity: %w", err)
		}
		id, err := uuid.Parse(rawID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse document id: %w", err)
		}
		meta := diff.Meta{ID: id, UserID: user}
		if rawTeam.Valid {
			team := rawTeam.String
			meta.TeamID = &team
		}
		out[id] = meta
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read document identities: %w", err)
	}
	return out, nil
}

// closeRows closes a result set, logging failures instead of shadowing the
// caller's error.
func closeRows(rows *sql.Rows, logger *slog.Logger) {
	if err := rows.Close(); err != nil {
		logger.Error("Failed to close rows", slog.Any("error", err))
	}
}

// toStrings renders UUIDs into their canonical textual form for array
// parameters.
func toStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// ident assembles a fully qualified, safely quoted PostgreSQL identifier.
func ident(schema, table string) string {
	// Example output: "public"."diff_state"
	return fmt.Sprintf("%s.%s", escape(schema), escape(table))
}

// escape safely wraps PostgreSQL identifiers in double quotes.
func escape(s string) string {
	return quote.Double(strings.ReplaceAll(s, `"`, `""`))
}

// literal safely wraps a string in single quotes for use as a SQL literal.
func literal(s string) string {
	return quote.Single(strings.ReplaceAll(s, "'", "''"))
}

var (
	_ diff.Store[*sql.Tx]   = (*Store)(nil)
	_ diff.Handler[*sql.Tx] = (*shares)(nil)
)
