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
	"log/slog"
	"time"
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
	// table is the name of the migration tracking table.
	table string
	// schema is the PostgreSQL schema containing the tracking table.
	schema string
	// lockID is an optional fixed identifier for advisory locks.
	lockID *int64
	// lockTimeout is the maximum wait time for acquiring the advisory lock.
	lockTimeout time.Duration
	// stmtTimeout is the maximum execution time for a single SQL statement.
	stmtTimeout time.Duration
	// logger is the structured logger for driver activity.
	logger *slog.Logger
}

// Option configures a PostgreSQL [Driver] instance.
type Option func(*config)

// WithTable sets a custom name for the migration tracking table.
//
// Empty string values are ignored.
func WithTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.table = name
		}
	}
}

// WithSchema sets a custom database schema for the tracking table.
//
// Empty string values are ignored.
func WithSchema(name string) Option {
	return func(c *config) {
		if name != "" {
			c.schema = name
		}
	}
}

// WithLockID sets a static identifier for the PostgreSQL advisory lock.
//
// If not provided, the identifier is derived from the schema and table name,
// so all migrator instances targeting the same tracking table contend for the
// same lock. Provide an explicit identifier to coordinate with external
// tooling or to avoid collisions with other advisory lock users.
func WithLockID(id int64) Option {
	return func(c *config) {
		c.lockID = &id
	}
}

// WithLockTimeout sets the maximum duration to wait for the advisory lock.
//
// If 0, it waits indefinitely (the default behavior).
func WithLockTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.lockTimeout = timeout
	}
}

// WithStatementTimeout sets a maximum duration for individual SQL statements.
//
// If 0, no timeout is applied (the default behavior).
func WithStatementTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.stmtTimeout = timeout
	}
}

// WithLogger injects a structured logger to record driver operations.
//
// Nil values are ignored, falling back to [slog.Default].
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}
