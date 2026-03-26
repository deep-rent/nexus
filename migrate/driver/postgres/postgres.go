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

	"github.com/deep-rent/nexus/internal/quote"
	"github.com/deep-rent/nexus/internal/schema"
	"github.com/deep-rent/nexus/migrate"
)

const (
	DefaultTable  = "migrations"
	DefaultSchema = "public"
)

// config holds the options for the PostgreSQL driver.
type config struct {
	table  string
	schema string
	logger *slog.Logger
}

// Option configures a PostgreSQL Driver.
type Option func(*config)

// WithTable sets the name of the migration tracking table.
func WithTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.table = name
		}
	}
}

// WithSchema sets the database schema for the tracking table.
func WithSchema(name string) Option {
	return func(c *config) {
		if name != "" {
			c.schema = name
		}
	}
}

// WithLogger sets the logger for the driver.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Driver implements migrate.Driver for PostgreSQL.
type Driver struct {
	db     *sql.DB
	lock   *sql.Conn
	table  string
	schema string
	ident  string
	lockID int64
	logger *slog.Logger
}

// New creates a new PostgreSQL migration driver with the provided options.
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
		db:     db,
		table:  cfg.table,
		schema: cfg.schema,
		ident:  fmt.Sprintf("%s.%s", escape(cfg.schema), escape(cfg.table)),
		logger: cfg.logger,
	}

	// Generate a random identifier for the table lock.
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random lock ID: %w", err)
	}
	d.lockID = int64(binary.BigEndian.Uint64(b[:]))

	return d, nil
}

// Parser returns the PostgreSQL-specific statement parser.
func (d *Driver) Parser() schema.Parser {
	return schema.Postgres
}

// Lock acquires a distributed lock via pg_advisory_lock.
func (d *Driver) Lock(ctx context.Context) error {
	if d.lock != nil {
		return errors.New("already locked")
	}

	d.logger.Debug("Acquiring advisory lock", slog.Int64("lock_id", d.lockID))
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire database connection: %w", err)
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

// Unlock releases the distributed lock.
func (d *Driver) Unlock(ctx context.Context) error {
	if d.lock == nil {
		return errors.New("not locked")
	}

	d.logger.Debug("Releasing advisory lock", slog.Int64("lock_id", d.lockID))
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

// Init creates the migrations tracking table if it doesn't already exist.
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

// Applied returns all successfully applied migration records.
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

// Force sets the database to the specified version and clears the dirty flag.
func (d *Driver) Force(ctx context.Context, version uint64) error {
	d.logger.Info("Forcing database version", slog.Uint64("version", version))

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

	var query string

	query = fmt.Sprintf(
		"UPDATE %s SET dirty = false WHERE version = $1",
		d.ident,
	)
	if _, err := tx.ExecContext(ctx, query, version); err != nil {
		return fmt.Errorf("failed to clear dirty flag: %w", err)
	}

	query = fmt.Sprintf("DELETE FROM %s WHERE version > $1", d.ident)
	if _, err := tx.ExecContext(ctx, query, version); err != nil {
		return fmt.Errorf("failed to delete newer versions: %w", err)
	}

	return tx.Commit()
}

// Execute runs the migration statements and records the state.
func (d *Driver) Execute(ctx context.Context, script migrate.Script) error {
	d.logger.Info(
		"Executing migration",
		slog.Uint64("version", script.Version),
		slog.Any("direction", script.Direction),
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

		if err := d.exec(ctx, tx, script.Statements); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	} else {
		d.logger.Debug("Running migration without transaction")
		if err := d.exec(ctx, d.db, script.Statements); err != nil {
			return err
		}
	}

	if err := d.setClean(ctx, script.Version, script.Direction); err != nil {
		return fmt.Errorf("failed to clear dirty state: %w", err)
	}
	return nil
}

// runner is an interface satisfied by both *sql.DB and *sql.Tx.
type runner interface {
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
}

// exec runs a series of SQL statements using the provided executor.
func (d *Driver) exec(
	ctx context.Context,
	run runner,
	statements []string,
) error {
	for i, stmt := range statements {
		d.logger.Debug("Executing statement", slog.Int("statement_index", i+1))
		if _, err := run.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute migration statement: %w", err)
		}
	}
	return nil
}

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

// Close closes the underlying database connection.
func (d *Driver) Close() error {
	d.logger.Debug("Closing database driver")
	return d.db.Close()
}

// escape safely escapes PostgreSQL identifiers.
func escape(s string) string {
	return quote.Double(strings.ReplaceAll(s, `"`, `""`))
}
