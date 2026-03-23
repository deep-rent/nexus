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
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
	`, tableName)

	if _, err := p.db.ExecContext(ctx, query); err != nil {
		return err
	}

	// Ensure checksum column exists for backward compatibility of tracking table.
	alter := fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS checksum VARCHAR(64) NOT NULL DEFAULT '';`, tableName)
	_, err := p.db.ExecContext(ctx, alter)
	return err
}

// Applied returns all successfully applied migration records.
func (p *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	query := fmt.Sprintf("SELECT version, checksum FROM %s ORDER BY version ASC", tableName)

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
		if err := rows.Scan(&rec.Version, &rec.Checksum); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Execute runs the migration statements and records the state.
func (p *Driver) Execute(
	ctx context.Context,
	version int64,
	direction migrate.Direction,
	checksum string,
	statements []string,
	useTx bool,
) error {
	if useTx {
		return p.executeTx(ctx, version, direction, checksum, statements)
	}
	return p.executeNoTx(ctx, version, direction, checksum, statements)
}

func (p *Driver) executeTx(
	ctx context.Context,
	version int64,
	direction migrate.Direction,
	checksum string,
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

	// 2. Update the tracking table safely
	if err := p.record(ctx, tx, version, direction, checksum); err != nil {
		return err
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (p *Driver) executeNoTx(
	ctx context.Context,
	version int64,
	direction migrate.Direction,
	checksum string,
	statements []string,
) error {
	for _, stmt := range statements {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute migration statement: %w", err)
		}
	}
	return p.record(ctx, p.db, version, direction, checksum)
}

func (p *Driver) record(ctx context.Context, exec execer, version int64, direction migrate.Direction, checksum string) error {
	switch direction {
	case migrate.Up:
		query := fmt.Sprintf("INSERT INTO %s (version, checksum) VALUES ($1, $2)", tableName)
		if _, err := exec.ExecContext(ctx, query, version, checksum); err != nil {
			return fmt.Errorf("failed to record migration: %w", err)
		}
	case migrate.Down:
		query := fmt.Sprintf("DELETE FROM %s WHERE version = $1", tableName)
		if _, err := exec.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}
	}
	return nil
}

// Close closes the underlying database connection.
func (p *Driver) Close() error {
	return p.db.Close()
}
