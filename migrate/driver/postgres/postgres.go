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
	"fmt"

	"github.com/deep-rent/nexus/migrate"
)

const tableName = "migrations"

// Driver implements migrate.Driver for PostgreSQL.
type Driver struct {
	db *sql.DB
}

// New creates a new PostgreSQL migration driver.
func New(db *sql.DB) *Driver {
	return &Driver{db: db}
}

// Init creates the migrations tracking table if it doesn't already exist.
func (p *Driver) Init(ctx context.Context) error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version BIGINT PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
	`, tableName)

	_, err := p.db.ExecContext(ctx, query)
	return err
}

// Applied returns all successfully applied migration versions.
func (p *Driver) Applied(ctx context.Context) ([]int64, error) {
	query := fmt.Sprintf("SELECT version FROM %s ORDER BY version ASC", tableName)

	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var versions []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return versions, nil
}

// Execute runs the migration payload and records the state in a single
// transaction.
func (p *Driver) Execute(
	ctx context.Context,
	version int64,
	direction migrate.Direction,
	payload string,
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

	// 1. Execute the actual migration SQL
	if _, err := tx.ExecContext(ctx, payload); err != nil {
		return fmt.Errorf("failed to execute migration payload: %w", err)
	}

	// 2. Update the tracking table safely using parameterized queries
	switch direction {
	case migrate.Up:
		query := fmt.Sprintf("INSERT INTO %s (version) VALUES ($1)", tableName)
		if _, err := tx.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to record migration: %w", err)
		}
	case migrate.Down:
		query := fmt.Sprintf("DELETE FROM %s WHERE version = $1", tableName)
		if _, err := tx.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Close closes the underlying database connection.
func (p *Driver) Close() error {
	return p.db.Close()
}
