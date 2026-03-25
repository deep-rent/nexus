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
	"database/sql"
	"errors"
	"fmt"

	"github.com/deep-rent/nexus/internal/schema"
	"github.com/deep-rent/nexus/migrate"
)

const (
	table     = "migrations" // Name of the tracking table
	tableLock = 145242119    // Arbitrary unique identifier for pg_advisory_lock
)

const (
	queryInit = `
		CREATE TABLE IF NOT EXISTS ` + table + ` (
			version BIGINT PRIMARY KEY,
			checksum BYTEA NOT NULL DEFAULT '\x',
			dirty BOOLEAN NOT NULL DEFAULT false,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`
	queryApplied       = "SELECT version, checksum, dirty FROM " + table + " ORDER BY version ASC"
	queryClearDirty    = "UPDATE " + table + " SET dirty = false WHERE version = $1"
	queryDeleteNewer   = "DELETE FROM " + table + " WHERE version > $1"
	querySetDirtyUp    = "INSERT INTO " + table + " (version, checksum, dirty) VALUES ($1, $2, true) ON CONFLICT (version) DO UPDATE SET dirty = true"
	querySetDirtyDown  = "UPDATE " + table + " SET dirty = true WHERE version = $1"
	queryDeleteVersion = "DELETE FROM " + table + " WHERE version = $1"
)

// Driver implements migrate.Driver for PostgreSQL.
type Driver struct {
	db   *sql.DB
	lock *sql.Conn
}

// New creates a new PostgreSQL migration driver.
func New(db *sql.DB) *Driver {
	return &Driver{db: db}
}

// Parser returns the PostgreSQL-specific statement parser.
func (p *Driver) Parser() schema.Parser {
	return schema.Postgres
}

// Lock acquires a distributed lock via pg_advisory_lock.
func (p *Driver) Lock(ctx context.Context) error {
	if p.lock != nil {
		return errors.New("already locked")
	}
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire database connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", tableLock); err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	p.lock = conn
	return nil
}

// Unlock releases the distributed lock.
func (p *Driver) Unlock(ctx context.Context) error {
	if p.lock == nil {
		return errors.New("not locked")
	}
	_, err := p.lock.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", tableLock)
	errClose := p.lock.Close()
	p.lock = nil
	if err != nil {
		return fmt.Errorf("failed to release advisory lock: %w", err)
	}
	return errClose
}

// Init creates the migrations tracking table if it doesn't already exist.
func (p *Driver) Init(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, queryInit)
	return err
}

// Applied returns all successfully applied migration records.
func (p *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	rows, err := p.db.QueryContext(ctx, queryApplied)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var records []migrate.Record
	for rows.Next() {
		var rec migrate.Record
		if err := rows.Scan(&rec.Version, &rec.Checksum, &rec.Dirty); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// Force sets the database to the specified version and clears the dirty flag.
func (p *Driver) Force(ctx context.Context, version uint64) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, queryClearDirty, version); err != nil {
		return fmt.Errorf("failed to clear dirty flag: %w", err)
	}

	if _, err := tx.ExecContext(ctx, queryDeleteNewer, version); err != nil {
		return fmt.Errorf("failed to delete newer versions: %w", err)
	}

	return tx.Commit()
}

// Execute runs the migration statements and records the state.
func (p *Driver) Execute(ctx context.Context, script migrate.Script) error {
	if err := p.setDirty(ctx, script.Version, script.Direction, script.Checksum); err != nil {
		return fmt.Errorf("failed to mark migration as dirty: %w", err)
	}

	if script.Tx {
		tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		if err := p.executeStatements(ctx, tx, script.Statements); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	} else {
		if err := p.executeStatements(ctx, p.db, script.Statements); err != nil {
			return err
		}
	}

	if err := p.setClean(ctx, script.Version, script.Direction); err != nil {
		return fmt.Errorf("failed to clear dirty state: %w", err)
	}
	return nil
}

// executor is an interface satisfied by both *sql.DB and *sql.Tx.
type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// executeStatements runs a series of SQL statements using the provided executor.
func (p *Driver) executeStatements(ctx context.Context, exec executor, statements []string) error {
	for _, stmt := range statements {
		if _, err := exec.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute migration statement: %w", err)
		}
	}
	return nil
}

func (p *Driver) setDirty(ctx context.Context, version uint64, direction migrate.Direction, checksum []byte) error {
	switch direction {
	case migrate.Up:
		if _, err := p.db.ExecContext(ctx, querySetDirtyUp, version, checksum); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	case migrate.Down:
		if _, err := p.db.ExecContext(ctx, querySetDirtyDown, version); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	}
	return nil
}

func (p *Driver) setClean(ctx context.Context, version uint64, direction migrate.Direction) error {
	switch direction {
	case migrate.Up:
		if _, err := p.db.ExecContext(ctx, queryClearDirty, version); err != nil {
			return fmt.Errorf("failed to clear dirty state: %w", err)
		}
	case migrate.Down:
		if _, err := p.db.ExecContext(ctx, queryDeleteVersion, version); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}
	}
	return nil
}

// Close closes the underlying database connection.
func (p *Driver) Close() error {
	return p.db.Close()
}
