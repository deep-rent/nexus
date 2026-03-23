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
	tableName = "migrations"
	lockID    = 96281735 // Arbitrary unique identifier for pg_advisory_lock
)

// Driver implements migrate.Driver for PostgreSQL.
type Driver struct {
	db       *sql.DB
	lockConn *sql.Conn
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
	if p.lockConn != nil {
		return errors.New("already locked")
	}
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire database connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	p.lockConn = conn
	return nil
}

// Unlock releases the distributed lock.
func (p *Driver) Unlock(ctx context.Context) error {
	if p.lockConn == nil {
		return errors.New("not locked")
	}
	_, err := p.lockConn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID)
	errClose := p.lockConn.Close()
	p.lockConn = nil
	if err != nil {
		return fmt.Errorf("failed to release advisory lock: %w", err)
	}
	return errClose
}

// Init creates the migrations tracking table if it doesn't already exist.
func (p *Driver) Init(ctx context.Context) error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version BIGINT PRIMARY KEY,
			checksum VARCHAR(64) NOT NULL DEFAULT '',
			dirty BOOLEAN NOT NULL DEFAULT false,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
	`, tableName)

	_, err := p.db.ExecContext(ctx, query)
	return err
}

// Applied returns all successfully applied migration records.
func (p *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	query := fmt.Sprintf("SELECT version, checksum, dirty FROM %s ORDER BY version ASC", tableName)

	rows, err := p.db.QueryContext(ctx, query)
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

	queryUpdate := fmt.Sprintf("UPDATE %s SET dirty = false WHERE version = $1", tableName)
	if _, err := tx.ExecContext(ctx, queryUpdate, version); err != nil {
		return fmt.Errorf("failed to clear dirty flag: %w", err)
	}

	queryDelete := fmt.Sprintf("DELETE FROM %s WHERE version > $1", tableName)
	if _, err := tx.ExecContext(ctx, queryDelete, version); err != nil {
		return fmt.Errorf("failed to delete newer versions: %w", err)
	}

	return tx.Commit()
}

// Execute runs the migration statements and records the state.
func (p *Driver) Execute(
	ctx context.Context,
	version uint64,
	direction migrate.Direction,
	checksum string,
	statements []string,
	useTx bool,
) error {
	if err := p.setDirty(ctx, version, direction, checksum); err != nil {
		return fmt.Errorf("failed to mark migration as dirty: %w", err)
	}

	var err error
	if useTx {
		err = p.executeTx(ctx, statements)
	} else {
		err = p.executeNoTx(ctx, statements)
	}

	if err != nil {
		return err
	}

	if err := p.clearDirty(ctx, version, direction); err != nil {
		return fmt.Errorf("failed to clear dirty state: %w", err)
	}

	return nil
}

func (p *Driver) executeTx(
	ctx context.Context,
	statements []string,
) error {
	// Begin transaction
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure rollback on panic or early return
	defer func() {
		_ = tx.Rollback()
	}()

	// 1. Execute the actual migration SQL statements
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute migration statement: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (p *Driver) executeNoTx(
	ctx context.Context,
	statements []string,
) error {
	for _, stmt := range statements {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute migration statement: %w", err)
		}
	}
	return nil
}

func (p *Driver) setDirty(ctx context.Context, version uint64, direction migrate.Direction, checksum string) error {
	switch direction {
	case migrate.Up:
		query := fmt.Sprintf("INSERT INTO %s (version, checksum, dirty) VALUES ($1, $2, true) ON CONFLICT (version) DO UPDATE SET dirty = true", tableName)
		if _, err := p.db.ExecContext(ctx, query, version, checksum); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	case migrate.Down:
		query := fmt.Sprintf("UPDATE %s SET dirty = true WHERE version = $1", tableName)
		if _, err := p.db.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to mark migration as dirty: %w", err)
		}
	}
	return nil
}

func (p *Driver) clearDirty(ctx context.Context, version uint64, direction migrate.Direction) error {
	switch direction {
	case migrate.Up:
		query := fmt.Sprintf("UPDATE %s SET dirty = false WHERE version = $1", tableName)
		if _, err := p.db.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to clear dirty state: %w", err)
		}
	case migrate.Down:
		query := fmt.Sprintf("DELETE FROM %s WHERE version = $1", tableName)
		if _, err := p.db.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}
	}
	return nil
}

// Close closes the underlying database connection.
func (p *Driver) Close() error {
	return p.db.Close()
}
