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

// Queries concatenate only the quoted identifier from quote.Ident; all
// values are passed as bind parameters:
//gosec:disable G202 -- identifiers are escaped, values are parameterized

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/dat/migrate"
	"github.com/deep-rent/nexus/dat/migrate/schema"
	"github.com/deep-rent/nexus/std/quote"
)



// Driver implements the [migrate.Driver] interface for PostgreSQL.
//
// It manages the database connection, distributed locks, and the execution of
// migration statements.
type Driver struct {
	// db is the underlying database connection pool.
	db *sql.DB
	// lock is a dedicated connection held while the advisory lock is active.
	lock *sql.Conn
	// table is the unquoted name of the tracking table.
	table string
	// schema is the unquoted database schema containing the table.
	schema string
	// ident is the precomputed, safely quoted schema and table identifier.
	ident string
	// lockID is the identifier used for pg_advisory_lock.
	lockID int64
	// lockTimeout is the maximum wait time for lock acquisition.
	lockTimeout time.Duration
	// stmtTimeout is the maximum duration for a single statement.
	stmtTimeout time.Duration
	// logger records driver operations.
	logger *slog.Logger
}

// New creates a new PostgreSQL migration driver.
//
// It uses the provided database connection and options. Unless overridden via
// [WithLockID], the advisory lock identifier is derived deterministically from
// the schema and table name, so that concurrent migrator instances targeting
// the same tracking table mutually exclude each other.
func New(db *sql.DB, opts ...Option) *Driver {
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
		ident:       quote.Ident(cfg.schema, cfg.table),
		lockTimeout: cfg.lockTimeout,
		stmtTimeout: cfg.stmtTimeout,
		logger:      cfg.logger,
	}

	if cfg.lockID != nil {
		d.lockID = *cfg.lockID
	} else {
		d.lockID = deriveLockID(cfg.schema, cfg.table)
	}

	return d
}

// deriveLockID hashes the schema and table name into a stable, non-negative
// advisory lock identifier.
//
// Deriving the identifier from the tracking table location guarantees that
// every migrator instance pointed at the same table competes for the same
// lock, while migrators using different tables remain independent.
func deriveLockID(schema, table string) int64 {
	h := fnv.New64a()
	_, _ = io.WriteString(h, schema)
	_, _ = io.WriteString(h, ".")
	_, _ = io.WriteString(h, table)
	return int64(h.Sum64() & 0x7FFFFFFFFFFFFFFF)
}

// LockID returns the advisory lock identifier used by this driver.
func (d *Driver) LockID() int64 {
	return d.lockID
}

// Parser returns the PostgreSQL-specific statement parser.
//
// This parser safely splits scripts while ignoring semicolons inside string
// literals, comments, and dollar-quoted blocks.
func (d *Driver) Parser() schema.Parser {
	return schema.Postgres
}

// Lock acquires an exclusive distributed lock using pg_advisory_lock.
//
// This prevents multiple migrator instances from running concurrently on the
// same database. It holds a dedicated connection for the duration of the lock
// and respects the configured lock timeout.
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
				log.Err(e),
			)
		}
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}

	d.lock = conn
	d.logger.Info("Advisory lock acquired")
	return nil
}

// Unlock releases the advisory lock and returns the connection to the pool.
//
// It releases the lock acquired via pg_advisory_unlock.
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
//
// It creates the table with columns for version, checksum, dirty state, and
// application timestamp if it is not already present.
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

// Applied retrieves all successfully applied migration records.
//
// The records are ordered by their version in ascending order.
func (d *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	d.logger.Debug("Fetching applied migrations")
	query := "SELECT version, checksum, dirty FROM " +
		d.ident + " ORDER BY version ASC"

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := rows.Close(); e != nil {
			d.logger.Error("Failed to close rows", log.Err(e))
		}
	}()

	var records []migrate.Record
	for rows.Next() {
		var rec migrate.Record
		var checksum []byte
		if err := rows.Scan(&rec.Version, &checksum, &rec.Dirty); err != nil {
			return nil, err
		}
		// Reject corrupt rows instead of silently zero-padding, which would
		// surface much later as a confusing checksum mismatch.
		if len(checksum) != len(rec.Checksum) {
			return nil, fmt.Errorf(
				"corrupt checksum for version %d: got %d bytes, want %d",
				rec.Version, len(checksum), len(rec.Checksum),
			)
		}
		copy(rec.Checksum[:], checksum)
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// withTx is an internal helper that manages serializable transactions.
func (d *Driver) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if e := tx.Rollback(); e != nil && !errors.Is(e, sql.ErrTxDone) {
			d.logger.Error(
				"Failed to rollback transaction",
				log.Err(e),
			)
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
//
// It clears the dirty flag for the target version and deletes any migration
// records with a version strictly greater than the target. This is typically
// used to recover from a dirty database state after human intervention.
func (d *Driver) Force(ctx context.Context, version int64) error {
	d.logger.Info("Forcing database version", slog.Int64("version", version))

	return d.withTx(ctx, func(tx *sql.Tx) error {
		queryUpdate := "UPDATE " + d.ident + " SET dirty = false WHERE version = $1"
		if _, err := tx.ExecContext(ctx, queryUpdate, version); err != nil {
			return fmt.Errorf("failed to clear dirty flag: %w", err)
		}

		queryDelete := "DELETE FROM " + d.ident + " WHERE version > $1"
		if _, err := tx.ExecContext(ctx, queryDelete, version); err != nil {
			return fmt.Errorf("failed to delete newer versions: %w", err)
		}

		return nil
	})
}

// Execute runs the provided migration script against the database.
//
// It marks the version as dirty, executes the statements, and clears the dirty
// state upon success. If execution fails, the database remains marked as dirty
// to prevent further automated migrations.
func (d *Driver) Execute(
	ctx context.Context,
	script migrate.ParsedScript,
) error {
	d.logger.Info(
		"Executing migration",
		slog.Int64("version", script.Version),
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
			// The transaction rolled back, so the schema is unchanged; undo
			// the dirty marker to spare the operator a manual Force. If the
			// cleanup itself fails, the marker stays and blocks further runs,
			// which is the safe direction to err in.
			if e := d.undoDirty(
				script.Version,
				script.Direction,
			); e != nil {
				d.logger.Error(
					"Failed to undo dirty marker after rollback",
					log.Err(e),
				)
			}
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

// runner is an interface satisfied by both [*sql.DB] and [*sql.Tx].
type runner interface {
	// ExecContext executes a query without returning any rows.
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
}

// execAll iterates through SQL statements and runs them sequentially.
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

// execOne isolates the execution of a single statement.
func (d *Driver) execOne(ctx context.Context, run runner, stmt string) error {
	if d.stmtTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.stmtTimeout)
		defer cancel()
	}
	_, err := run.ExecContext(ctx, stmt)
	return err
}

// setDirty records a migration attempt in the tracking table.
//
// For upward migrations, it inserts or updates a row. For downward migrations,
// it updates the existing row.
func (d *Driver) setDirty(
	ctx context.Context,
	version int64,
	direction migrate.Direction,
	checksum [32]byte,
) error {
	d.logger.Debug(
		"Marking migration as dirty",
		slog.Int64("version", version),
	)

	switch direction {
	case migrate.Up:
		query := "INSERT INTO " + d.ident +
			" (version, checksum, dirty) VALUES ($1, $2, true) " +
			"ON CONFLICT (version) DO UPDATE " +
			"SET dirty = true, checksum = EXCLUDED.checksum"
		if _, err := d.db.ExecContext(
			ctx,
			query,
			version,
			checksum[:],
		); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	case migrate.Down:
		query := "UPDATE " + d.ident + " SET dirty = true WHERE version = $1"
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

// undoDirty reverts the marker written by setDirty after a transactional
// migration failed and rolled back cleanly.
//
// For upward migrations, it deletes the record inserted for the attempt. For
// downward migrations, it restores the existing record to a clean state. It
// runs on a fresh context so cleanup still succeeds when the migration failed
// due to cancellation of the original context.
func (d *Driver) undoDirty(version int64, direction migrate.Direction) error {
	d.logger.Debug(
		"Undoing dirty marker after rollback",
		slog.Int64("version", version),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch direction {
	case migrate.Up:
		query := "DELETE FROM " + d.ident + " WHERE version = $1 AND dirty"
		if _, err := d.db.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to delete dirty record: %w", err)
		}
	case migrate.Down:
		query := "UPDATE " + d.ident + " SET dirty = false WHERE version = $1"
		if _, err := d.db.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to restore clean state: %w", err)
		}
	}
	return nil
}

// setClean finalizes a successful migration by removing the dirty state.
//
// For upward migrations, it sets dirty to false. For downward migrations, it
// removes the version record entirely.
func (d *Driver) setClean(
	ctx context.Context,
	version int64,
	direction migrate.Direction,
) error {
	d.logger.Debug("Clearing dirty state", slog.Int64("version", version))

	switch direction {
	case migrate.Up:
		query := "UPDATE " + d.ident + " SET dirty = false WHERE version = $1"
		if _, err := d.db.ExecContext(
			ctx,
			query,
			version,
		); err != nil {
			return fmt.Errorf("failed to clear dirty state: %w", err)
		}
	case migrate.Down:
		query := "DELETE FROM " + d.ident + " WHERE version = $1"
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
