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

// Default names for the store's bookkeeping objects.
const (
	// DefaultSchema is the default PostgreSQL schema.
	DefaultSchema = "public"
	// DefaultMutationsTable is the default name of the mutation
	// deduplication table.
	DefaultMutationsTable = "document_mutations"
	// DefaultTombstonesTable is the default name of the tombstone table.
	DefaultTombstonesTable = "document_tombstones"
	// DefaultStateTable is the default name of the state table holding the
	// retention floor.
	DefaultStateTable = "document_state"
	// DefaultSharesTable is the default name of the share grants table.
	DefaultSharesTable = "document_shares"
	// DefaultSequence is the default name of the global feed sequence.
	DefaultSequence = "document_seq"
)

// Default retention windows enforced by [Retention].
const (
	// DefaultMutationRetention is the default age above which mutation
	// deduplication records are pruned.
	DefaultMutationRetention = 30 * 24 * time.Hour
	// DefaultTombstoneRetention is the default age above which tombstones
	// are pruned, advancing the retention floor.
	DefaultTombstoneRetention = 90 * 24 * time.Hour
)

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
// The reference SQL files under migrations/ only cover the default names;
// adjust the application's schema migrations accordingly.
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
// The reference SQL files under migrations/ only cover the default names;
// adjust the application's schema migrations accordingly.
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
// The reference SQL files under migrations/ only cover the default names;
// adjust the application's schema migrations accordingly.
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
// The reference SQL files under migrations/ only cover the default names;
// adjust the application's schema migrations accordingly.
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
// The reference SQL files under migrations/ only cover the default names;
// adjust the application's schema migrations accordingly.
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
// The reference SQL files under migrations/ only cover the default names;
// adjust the application's schema migrations accordingly.
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

// tableConfig holds the internal configuration options of a [Table].
type tableConfig struct {
	// schema overrides the store's default schema for this table.
	schema string
	// parent is the table name of the ownership parent (child tables only).
	parent string
	// ref is the column and JSON field referencing the parent row.
	ref string
}

// TableOption configures a single [Table] registration.
type TableOption func(*tableConfig)

// WithTableSchema sets a custom database schema for this table, overriding
// the store's default.
//
// Empty string values are ignored.
func WithTableSchema(name string) TableOption {
	return func(c *tableConfig) {
		if name != "" {
			c.schema = name
		}
	}
}

// WithParent marks the table as a child of the given parent table (by its
// table name, which must already be registered with the store). The ref
// argument names both the child column and the JSON payload field that
// reference the parent row's id; by convention they must be equal.
//
// Empty string values are ignored.
func WithParent(parent, ref string) TableOption {
	return func(c *tableConfig) {
		if parent != "" && ref != "" {
			c.parent = parent
			c.ref = ref
		}
	}
}

// RetentionOption configures a [Retention] task.
type RetentionOption func(*Retention)

// WithMutationRetention overrides [DefaultMutationRetention]. The window
// bounds idempotent deduplication: a client replaying a change set older
// than the window re-applies it. This is harmless to state (last-write-wins
// skips equal timestamps on upserts and deletes alike), so the window
// merely needs to exceed the longest realistic retry horizon.
//
// Non-positive values are ignored.
func WithMutationRetention(d time.Duration) RetentionOption {
	return func(r *Retention) {
		if d > 0 {
			r.mutations = d
		}
	}
}

// WithTombstoneRetention overrides [DefaultTombstoneRetention]. The window
// bounds how long a device may stay offline without losing its cursor:
// pruning advances the retention floor, and clients whose cursor predates
// it are forced into a full resync from zero.
//
// Non-positive values are ignored.
func WithTombstoneRetention(d time.Duration) RetentionOption {
	return func(r *Retention) {
		if d > 0 {
			r.tombstones = d
		}
	}
}
