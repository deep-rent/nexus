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

// Package postgres provides a PostgreSQL-specific driver for the migrate
// package.
//
// Its primary responsibility is to execute database migrations, manage
// the state of applied migrations, and ensure concurrent safety using
// PostgreSQL advisory locks. The driver supports configurable schema and
// table names for state tracking, structured logging, and transactional
// execution of migration scripts.
//
// Example usage:
//
//	db, _ := sql.Open("postgres", "postgres://user:pass@localhost:5432/db")
//	driver, err := postgres.New(db,
//	    postgres.WithSchema("public"),
//	    postgres.WithTable("schema_migrations"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/deep-rent/nexus/internal/quote"
	"github.com/deep-rent/nexus/internal/schema"
	"github.com/deep-rent/nexus/migrate"
)

const (
	// DefaultTable is the default name for the migration tracking table.
	DefaultTable = "migrations"
	// DefaultSchema is the default PostgreSQL schema where the tracking table
	// resides.
	DefaultSchema = "public"
)

// config holds the internal configuration options for the PostgreSQL driver.
type config struct {
	table       string
	schema      string
	lockID      *int64
	lockTimeout time.Duration
	stmtTimeout time.Duration
	logger      *slog.Logger
}

// Option configures a PostgreSQL Driver instance.
type Option func(*config)

// WithTable sets a custom name for the migration tracking table.
// Empty string values are ignored.
func WithTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.table = name
		}
	}
}

// WithSchema sets a custom database schema for the tracking table.
// Empty string values are ignored.
func WithSchema(name string) Option {
	return func(c *config) {
		if name != "" {
			c.schema = name
		}
	}
}

// WithLockID sets a static identifier for the PostgreSQL advisory lock.
// If not provided, a random 64-bit identifier is securely generated.
// This is primarily intended for testing lock contention.
func WithLockID(id int64) Option {
	return func(c *config) {
		c.lockID = &id
	}
}

// WithLockTimeout sets the maximum duration to wait when attempting to acquire
// the advisory lock. If 0, it waits indefinitely (the default behavior).
func WithLockTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.lockTimeout = timeout
	}
}

// WithStatementTimeout sets a maximum duration for individual migration
// statements to execute. If 0, no timeout is applied (the default behavior).
func WithStatementTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.stmtTimeout = timeout
	}
}

// WithLogger injects a structured logger to record driver operations.
// Nil values are ignored, falling back to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Driver implements the migrate.Driver interface for PostgreSQL.
// It manages the database connection, distributed locks, and the execution
// of migration statements.
type Driver struct {
	db          *sql.DB       // Underlying database connection pool
	lock        *sql.Conn     // Dedicated connection held while locked
	table       string        // Unquoted name of the tracking table
	schema      string        // Unquoted database schema containing the table
	ident       string        // Precomputed schema and table identifier
	lockID      int64         // Random integer used for the lock
	lockTimeout time.Duration // Max time to wait for lock acquisition
	stmtTimeout time.Duration // Max time per individual SQL statement
	logger      *slog.Logger  // Logger for recording driver operations
}

// New creates a new PostgreSQL migration driver using the provided database
// connection and options. It generates a unique cryptographic identifier
// to be used for advisory locks to prevent concurrent migration conflicts.
// It returns an error if the lock identifier generation fails.
func New(db *sql.DB, opts ...Option) (*Driver, error) {
	cfg := &config{
		table:  DefaultTable,
		schema: DefaultSchema,
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	d := &Driver{
		db:          db,
		table:       cfg.table,
		schema:      cfg.schema,
		ident:       ident(cfg.schema, cfg.table),
		lockTimeout: cfg.lockTimeout,
		stmtTimeout: cfg.stmtTimeout,
		logger:      cfg.logger,
	}

	if cfg.lockID != nil {
		d.lockID = *cfg.lockID
	} else {
		// Generate a random identifier for the table lock.
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("failed to generate random lock ID: %w", err)
		}
		d.lockID = int64(binary.BigEndian.Uint64(b[:]))
	}

	return d, nil
}

// Parser returns the PostgreSQL-specific statement parser from the schema
// package. This parser safely splits scripts while ignoring semicolons inside
// string literals, comments, and dollar-quoted blocks.
func (d *Driver) Parser() schema.Parser {
	return schema.Postgres
}

// Lock acquires an exclusive distributed lock using pg_advisory_lock.
// This prevents multiple migrator instances from running concurrently on the
// same database. It holds a dedicated connection for the duration of the lock.
// It respects the configured lock timeout, ensuring it fails fast if blocked.
func (d *Driver) Lock(ctx context.Context) error {
	if d.lock != nil {
		return errors.New("already locked")
	}

	d.logger.Debug("Acquiring advisory lock", slog.Int64("id", d.lockID))
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire database connection: %w", err)
	}

	// Apply lock timeout if configured
	if d.lockTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.lockTimeout)
		defer cancel()
	}

	if _, err := conn.ExecContext(
		ctx,
		"SELECT pg_advisory_lock($1)",
		d.lockID,
	); err != nil {
		if e := conn.Close(); e != nil {
			d.logger.Error(
				"Failed to close connection after lock failure",
				slog.Any("error", e),
			)
		}
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}

	d.lock = conn
	d.logger.Info("Advisory lock acquired")
	return nil
}

// Unlock releases the exclusive distributed lock acquired via
// pg_advisory_unlock and returns the dedicated connection back to the pool.
func (d *Driver) Unlock(ctx context.Context) error {
	if d.lock == nil {
		return errors.New("not locked")
	}

	d.logger.Debug("Releasing advisory lock", slog.Int64("id", d.lockID))
	_, err := d.lock.ExecContext(
		ctx,
		"SELECT pg_advisory_unlock($1)",
		d.lockID,
	)

	e := d.lock.Close()
	d.lock = nil

	if err != nil {
		return fmt.Errorf("failed to release advisory lock: %w", err)
	}

	d.logger.Info("Advisory lock released")
	return e
}

// Init ensures that the tracking table exists in the target schema.
// It creates the table with columns for version, checksum, dirty state,
// and application timestamp if it is not already present.
func (d *Driver) Init(ctx context.Context) error {
	d.logger.Debug(
		"Initializing migration table if missing",
		slog.String("name", d.table),
		slog.String("schema", d.schema),
	)

	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version    BIGINT PRIMARY KEY,
			checksum   BYTEA NOT NULL DEFAULT '\x',
			dirty      BOOLEAN NOT NULL DEFAULT false,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`, d.ident)

	_, err := d.db.ExecContext(ctx, query)
	return err
}

// Applied retrieves all successfully applied migration records from the
// database, ordered by their version in ascending order.
func (d *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	d.logger.Debug("Fetching applied migrations")
	query := fmt.Sprintf(
		"SELECT version, checksum, dirty FROM %s ORDER BY version ASC",
		d.ident,
	)

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := rows.Close(); e != nil {
			d.logger.Error("Failed to close rows", slog.Any("error", e))
		}
	}()

	var records []migrate.Record
	for rows.Next() {
		var rec migrate.Record
		var checksum []byte
		if err := rows.Scan(&rec.Version, &checksum, &rec.Dirty); err != nil {
			return nil, err
		}
		copy(rec.Checksum[:], checksum)
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// withTx is an internal helper that manages the boilerplate of executing
// a serializable transaction, ensuring safe rollback or commit.
func (d *Driver) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if e := tx.Rollback(); e != nil && !errors.Is(e, sql.ErrTxDone) {
			d.logger.Error("Failed to rollback transaction", slog.Any("error", e))
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// Force manually sets the database to the specified version.
// It clears the dirty flag for the target version and deletes any migration
// records with a version strictly greater than the target. This is typically
// used to recover from a dirty database state after human intervention.
// It operates within a serializable transaction.
func (d *Driver) Force(ctx context.Context, version uint64) error {
	d.logger.Info("Forcing database version", slog.Uint64("version", version))

	return d.withTx(ctx, func(tx *sql.Tx) error {
		queryUpdate := fmt.Sprintf(
			"UPDATE %s SET dirty = false WHERE version = $1", d.ident,
		)
		if _, err := tx.ExecContext(ctx, queryUpdate, version); err != nil {
			return fmt.Errorf("failed to clear dirty flag: %w", err)
		}

		queryDelete := fmt.Sprintf(
			"DELETE FROM %s WHERE version > $1", d.ident,
		)
		if _, err := tx.ExecContext(ctx, queryDelete, version); err != nil {
			return fmt.Errorf("failed to delete newer versions: %w", err)
		}

		return nil
	})
}

// Execute runs the provided migration script against the database.
//
// It performs a three-step process:
//  1. Marks the target migration version as dirty in the tracking table.
//  2. Executes the parsed statements sequentially (optionally within a
//     transaction).
//  3. Clears the dirty state or removes the record (depending on the direction)
//     upon success.
//
// If an error occurs during execution, the database remains marked as dirty
// to prevent further automated migrations until the issue is manually resolved.
func (d *Driver) Execute(
	ctx context.Context,
	script migrate.ParsedScript,
) error {
	d.logger.Info(
		"Executing migration",
		slog.Uint64("version", script.Version),
		slog.String("direction", script.Direction.String()),
	)

	if err := d.setDirty(
		ctx,
		script.Version,
		script.Direction,
		script.Checksum,
	); err != nil {
		return fmt.Errorf("failed to mark migration as dirty: %w", err)
	}

	if script.Tx {
		d.logger.Debug("Running migration in transaction")
		err := d.withTx(ctx, func(tx *sql.Tx) error {
			return d.execAll(ctx, tx, script.Statements)
		})
		if err != nil {
			return err
		}
	} else {
		d.logger.Debug("Running migration without transaction")
		if err := d.execAll(ctx, d.db, script.Statements); err != nil {
			return err
		}
	}

	if err := d.setClean(ctx, script.Version, script.Direction); err != nil {
		return fmt.Errorf("failed to clear dirty state: %w", err)
	}
	return nil
}

// runner is an interface satisfied by both *sql.DB and *sql.Tx, allowing
// statements to be executed either transactionally or non-transactionally.
type runner interface {
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
}

// execAll iterates through a slice of SQL statements and runs them sequentially
// using the provided runner.
// execAll iterates through a slice of SQL statements and runs them sequentially
// using the provided runner.
func (d *Driver) execAll(
	ctx context.Context,
	run runner,
	statements []string,
) error {
	for i, stmt := range statements {
		d.logger.Debug("Executing statement", slog.Int("index", i+1))
		if err := d.execOne(ctx, run, stmt); err != nil {
			return fmt.Errorf("statement %d failed: %w", i+1, err)
		}
	}
	return nil
}

// execOne isolates the execution of a single statement so that the context
// cancellation (defer cancel()) fires immediately after the statement finishes,
// preventing resource leaks in the loop.
func (d *Driver) execOne(ctx context.Context, run runner, stmt string) error {
	if d.stmtTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.stmtTimeout)
		defer cancel()
	}
	_, err := run.ExecContext(ctx, stmt)
	return err
}

// setDirty records a migration attempt in the tracking table, flagging it as
// incomplete. For upward migrations, it inserts a new row or updates an
// existing one. For downward migrations, it updates the existing row.
func (d *Driver) setDirty(
	ctx context.Context,
	version uint64,
	direction migrate.Direction,
	checksum [32]byte,
) error {
	d.logger.Debug("Marking migration as dirty", slog.Uint64("version", version))

	switch direction {
	case migrate.Up:
		query := fmt.Sprintf(
			"INSERT INTO %s (version, checksum, dirty) VALUES ($1, $2, true) "+
				"ON CONFLICT (version) DO UPDATE SET dirty = true",
			d.ident,
		)
		if _, err := d.db.ExecContext(
			ctx,
			query,
			version,
			checksum[:],
		); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	case migrate.Down:
		query := fmt.Sprintf(
			"UPDATE %s SET dirty = true WHERE version = $1",
			d.ident,
		)
		if _, err := d.db.ExecContext(
			ctx,
			query,
			version,
		); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	}
	return nil
}

// setClean finalizes a successful migration by removing the dirty state.
// For upward migrations, it sets the dirty boolean to false. For downward
// migrations, it entirely removes the version record from the tracking table.
func (d *Driver) setClean(
	ctx context.Context,
	version uint64,
	direction migrate.Direction,
) error {
	d.logger.Debug("Clearing dirty state", slog.Uint64("version", version))

	switch direction {
	case migrate.Up:
		query := fmt.Sprintf(
			"UPDATE %s SET dirty = false WHERE version = $1",
			d.ident,
		)
		if _, err := d.db.ExecContext(
			ctx,
			query,
			version,
		); err != nil {
			return fmt.Errorf("failed to clear dirty state: %w", err)
		}
	case migrate.Down:
		query := fmt.Sprintf(
			"DELETE FROM %s WHERE version = $1",
			d.ident,
		)
		if _, err := d.db.ExecContext(
			ctx,
			query,
			version,
		); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}
	}
	return nil
}

// Close gracefully closes the underlying database connection.
func (d *Driver) Close() error {
	d.logger.Debug("Closing database driver")
	return d.db.Close()
}

// ident assembles a fully qualified, safely quoted PostgreSQL identifier by
// combining a schema name and a table name.
//
// Example output: "public"."migrations"
func ident(schema, table string) string {
	return fmt.Sprintf("%s.%s", escape(schema), escape(table))
}

// escape safely wraps PostgreSQL identifiers in double quotes, escaping any
// internal double quotes to prevent syntax errors or injection vectors.
func escape(s string) string {
	return quote.Double(strings.ReplaceAll(s, `"`, `""`))
}
