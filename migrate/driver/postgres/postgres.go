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

	"github.com/deep-rent/nexus/internal/schema"
	"github.com/deep-rent/nexus/migrate"
)

const (
	DefaultTable  = "migrations"
	DefaultSchema = "public"
)

// Option configures a PostgreSQL Driver.
type Option func(*Driver)

// WithTable sets the name of the migration tracking table.
func WithTable(name string) Option {
	return func(d *Driver) {
		if name != "" {
			d.tableName = name
		}
	}
}

// WithSchema sets the database schema for the tracking table.
func WithSchema(name string) Option {
	return func(d *Driver) {
		if name != "" {
			d.schemaName = name
		}
	}
}

// Driver implements migrate.Driver for PostgreSQL.
type Driver struct {
	db         *sql.DB
	lock       *sql.Conn
	tableName  string
	schemaName string
	lockID     int64

	// Pre-compiled, instance-specific queries
	qCreate       string
	qApplied      string
	qSetClean     string
	qDeleteNewer  string
	qSetDirtyUp   string
	qSetDirtyDown string
	qDelete       string
}

// New creates a new PostgreSQL migration driver with the provided options.
func New(db *sql.DB, opts ...Option) (*Driver, error) {
	d := &Driver{
		db:         db,
		tableName:  DefaultTable,
		schemaName: DefaultSchema,
	}

	for _, opt := range opts {
		opt(d)
	}

	// Generate a secure, random 64-bit identifier for pg_advisory_lock
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random lock ID: %w", err)
	}
	d.lockID = int64(binary.BigEndian.Uint64(b[:]))

	d.init()
	return d, nil
}

// init formats the necessary SQL statements using the configured
// schema and table identifiers, safely quoting them to prevent syntax errors.
func (d *Driver) init() {
	ident := fmt.Sprintf(`"%s"."%s"`, d.schemaName, d.tableName)

	d.qCreate = fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version    BIGINT PRIMARY KEY,
			checksum   BYTEA NOT NULL DEFAULT '\x',
			dirty      BOOLEAN NOT NULL DEFAULT false,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`, ident)

	d.qApplied = fmt.Sprintf("SELECT version, checksum, dirty FROM %s ORDER BY version ASC", ident)
	d.qDelete = fmt.Sprintf("DELETE FROM %s WHERE version = $1", ident)
	d.qDeleteNewer = fmt.Sprintf("DELETE FROM %s WHERE version > $1", ident)
	d.qSetClean = fmt.Sprintf("UPDATE %s SET dirty = false WHERE version = $1", ident)
	d.qSetDirtyUp = fmt.Sprintf("INSERT INTO %s (version, checksum, dirty) VALUES ($1, $2, true) ON CONFLICT (version) DO UPDATE SET dirty = true", ident)
	d.qSetDirtyDown = fmt.Sprintf("UPDATE %s SET dirty = true WHERE version = $1", ident)
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
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire database connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", d.lockID); err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	d.lock = conn
	return nil
}

// Unlock releases the distributed lock.
func (d *Driver) Unlock(ctx context.Context) error {
	if d.lock == nil {
		return errors.New("not locked")
	}
	_, err := d.lock.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", d.lockID)
	e := d.lock.Close()
	d.lock = nil
	if err != nil {
		return fmt.Errorf("failed to release advisory lock: %w", err)
	}
	return e
}

// Init creates the migrations tracking table if it doesn't already exist.
func (d *Driver) Init(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, d.qCreate)
	return err
}

// Applied returns all successfully applied migration records.
func (d *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	rows, err := d.db.QueryContext(ctx, d.qApplied)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
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
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, d.qSetClean, version); err != nil {
		return fmt.Errorf("failed to clear dirty flag: %w", err)
	}

	if _, err := tx.ExecContext(ctx, d.qDeleteNewer, version); err != nil {
		return fmt.Errorf("failed to delete newer versions: %w", err)
	}

	return tx.Commit()
}

// Execute runs the migration statements and records the state.
func (d *Driver) Execute(ctx context.Context, script migrate.Script) error {
	if err := d.setDirty(
		ctx,
		script.Version,
		script.Direction,
		script.Checksum,
	); err != nil {
		return fmt.Errorf("failed to mark migration as dirty: %w", err)
	}

	if script.Tx {
		tx, err := d.db.BeginTx(ctx, &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		})
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		if err := d.exec(ctx, tx, script.Statements); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	} else {
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
	for _, stmt := range statements {
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
	switch direction {
	case migrate.Up:
		if _, err := d.db.ExecContext(
			ctx,
			d.qSetDirtyUp,
			version,
			checksum[:],
		); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	case migrate.Down:
		if _, err := d.db.ExecContext(
			ctx,
			d.qSetDirtyDown,
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
	switch direction {
	case migrate.Up:
		if _, err := d.db.ExecContext(
			ctx,
			d.qSetClean,
			version,
		); err != nil {
			return fmt.Errorf("failed to clear dirty state: %w", err)
		}
	case migrate.Down:
		if _, err := d.db.ExecContext(
			ctx,
			d.qDelete,
			version,
		); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}
	}
	return nil
}

// Close closes the underlying database connection.
func (d *Driver) Close() error {
	return d.db.Close()
}
