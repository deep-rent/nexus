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

// Package migrate provides the core orchestration logic for database
// migrations.
package migrate

import (
	"cmp"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"slices"

	"github.com/deep-rent/nexus/internal/schema"
)

// Direction indicates whether a migration is being applied or reverted.
type Direction string

const (
	Up   Direction = "up"
	Down Direction = "down"
)

// Record represents a successfully applied migration stored in the database.
type Record struct {
	Version  uint64
	Checksum [32]byte
	Dirty    bool
}

// Driver is the interface that database-specific backends must implement.
type Driver interface {
	Parser() schema.Parser
	Init(ctx context.Context) error
	Lock(ctx context.Context) error
	Unlock(ctx context.Context) error
	Applied(ctx context.Context) ([]Record, error)
	Force(ctx context.Context, version uint64) error
	Execute(ctx context.Context, script Script) error
	Close() error
}

// Source provides migrations.
type Source interface {
	// List returns a list of all available migration files.
	// The Migrator will handle hashing the content and sorting the results.
	List() ([]SourceFile, error)
}

// SourceFile represents an unhashed migration script retrieved from a Source.
type SourceFile struct {
	Version     uint64    // Unique sequence number
	Description string    // Human-readable description
	Direction   Direction // "up" or "down"
	Path        string    // Path identifier within the source
	Content     []byte    // Raw SQL content
	Tx          bool      // Indicates whether to run in a transaction
}

// Script holds the parameters required to execute a migration.
type Script struct {
	Version    uint64
	Direction  Direction
	Checksum   [32]byte
	Statements []string
	Tx         bool
}

// Migration represents a parsed migration file.
type Migration struct {
	Version     uint64    // Unique sequence number of the migration
	Description string    // A human-readable description of the migration
	Direction   Direction // Indicates if this is an "up" or "down" migration
	Path        string    // Path identifier within the source
	Checksum    [32]byte  // SHA-256 hash of the content
	Content     []byte    // Raw SQL content of the migration file
	Tx          bool      // Indicates whether to run in a transaction
}

// Compare returns an integer comparing two migrations to establish a strict
// ordering. The result will be 0 if m == other, -1 if m < other, and +1 if
// m > other.
//
// Migrations are ordered primarily by version in ascending order. If two
// migrations share the same version, they are secondarily ordered by direction
// (alphabetically, so "down" comes before "up") to guarantee deterministic
// sorting.
func (m Migration) Compare(other Migration) int {
	if n := cmp.Compare(m.Version, other.Version); n != 0 {
		return n
	}
	return cmp.Compare(m.Direction, other.Direction)
}

// Migrator orchestrates the execution of database migrations.
type Migrator struct {
	source Source
	driver Driver
	logger *slog.Logger
}

// Option configures a Migrator instance.
type Option func(*Migrator)

// WithSource sets the migration source.
func WithSource(source Source) Option {
	return func(m *Migrator) {
		if source != nil {
			m.source = source
		}
	}
}

// WithDriver sets the database driver.
func WithDriver(driver Driver) Option {
	return func(m *Migrator) {
		if driver != nil {
			m.driver = driver
		}
	}
}

// WithLogger sets the logger for the migrator.
func WithLogger(logger *slog.Logger) Option {
	return func(m *Migrator) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// New creates a new Migrator instance. It returns an error if the required
// dependencies (Source and Driver) are not provided.
func New(opts ...Option) (*Migrator, error) {
	m := &Migrator{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.source == nil {
		return nil, fmt.Errorf("migrate: source is required")
	}
	if m.driver == nil {
		return nil, fmt.Errorf("migrate: driver is required")
	}
	return m, nil
}

// lock is a helper that acquires the driver lock, ensures the tracking table is
// initialized, executes the provided function, and guarantees the lock is
// released afterward.
func (m *Migrator) lock(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if err := m.driver.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	defer func() {
		if err := m.driver.Unlock(context.Background()); err != nil {
			m.logger.Error("Failed to release lock", slog.Any("error", err))
		}
	}()

	if err := m.driver.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize driver: %w", err)
	}

	return fn(ctx)
}

// files fetches all available migrations from the source, calculates their
// cryptographic checksums, maps them to domain objects, and strictly sorts them.
func (m *Migrator) files() ([]Migration, error) {
	files, err := m.source.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list source files: %w", err)
	}

	var migrations []Migration
	for _, raw := range files {
		migrations = append(migrations, Migration{
			Version:     raw.Version,
			Description: raw.Description,
			Direction:   raw.Direction,
			Path:        raw.Path,
			Checksum:    sha256.Sum256(raw.Content),
			Content:     raw.Content,
			Tx:          raw.Tx,
		})
	}

	slices.SortFunc(migrations, Migration.Compare)
	return migrations, nil
}

// Up applies all pending migrations in ascending order.
func (m *Migrator) Up(ctx context.Context) error {
	return m.lock(ctx, func(ctx context.Context) error {
		pending, err := m.Pending(ctx)
		if err != nil {
			return err
		}

		if len(pending) == 0 {
			m.logger.Info("Migrations are up to date")
			return nil
		}

		m.logger.Info(
			"Applying pending migrations",
			slog.Int("count", len(pending)),
		)
		for _, p := range pending {
			if err := m.run(ctx, p); err != nil {
				return err
			}
		}
		m.logger.Info("All migrations applied successfully")
		return nil
	})
}

// Down reverts the most recently applied migration.
func (m *Migrator) Down(ctx context.Context) error {
	return m.lock(ctx, func(ctx context.Context) error {
		applied, err := m.Applied(ctx)
		if err != nil {
			return err
		}
		if len(applied) == 0 {
			m.logger.Info("No applied migrations to revert")
			return nil
		}

		// Get the last applied migration to revert
		last := applied[len(applied)-1]

		// Fetch and strictly sort files
		files, err := m.files()
		if err != nil {
			return err
		}

		for _, f := range files {
			if f.Version == last.Version && f.Direction == Down {
				err := m.run(ctx, f)
				if err == nil {
					m.logger.Info(
						"Migration reverted successfully",
						slog.Uint64("version", f.Version),
					)
				}
				return err
			}
		}
		return fmt.Errorf(
			"down migration file not found for version %d",
			last.Version,
		)
	})
}

// Force manually sets the database to the specified version and clears the
// dirty flag. It should be used to resolve a dirty state after human
// intervention.
func (m *Migrator) Force(ctx context.Context, version uint64) error {
	return m.lock(ctx, func(ctx context.Context) error {
		if err := m.driver.Force(ctx, version); err != nil {
			return fmt.Errorf("failed to force version: %w", err)
		}
		m.logger.Info(
			"Successfully forced migration version",
			slog.Uint64("version", version),
		)
		return nil
	})
}

// MigrateTo applies or reverts migrations to reach the target version.
func (m *Migrator) MigrateTo(ctx context.Context, target uint64) error {
	return m.lock(ctx, func(ctx context.Context) error {
		records, files, err := m.load(ctx)
		if err != nil {
			return err
		}
		applied := toLookup(records)

		// Revert applied migrations strictly greater than the target version in
		// descending order.
		for i := len(records) - 1; i >= 0; i-- {
			v := records[i].Version
			if v > target {
				found := false
				for _, f := range files {
					if f.Version == v && f.Direction == Down {
						if err := m.run(ctx, f); err != nil {
							return err
						}
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("down migration file not found for version %d", v)
				}
				applied[v] = false
			}
		}

		// Apply pending migrations less than or equal to the target version in
		// ascending order.
		for _, f := range files {
			if f.Direction == Up && f.Version <= target && !applied[f.Version] {
				if err := m.run(ctx, f); err != nil {
					return err
				}
				applied[f.Version] = true
			}
		}

		return nil
	})
}

// Pending returns a list of "Up" migrations that have not yet been applied.
func (m *Migrator) Pending(ctx context.Context) ([]Migration, error) {
	records, files, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	applied := toLookup(records)

	var out []Migration
	for _, f := range files {
		if f.Direction == Up && !applied[f.Version] {
			out = append(out, f)
		}
	}

	return out, nil
}

// Applied returns a list of "Up" migrations that have already been executed.
func (m *Migrator) Applied(ctx context.Context) ([]Migration, error) {
	records, files, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	applied := toLookup(records)

	var out []Migration
	for _, f := range files {
		if f.Direction == Up && applied[f.Version] {
			out = append(out, f)
		}
	}

	return out, nil
}

// run reads the migration payload and executes it via the driver.
func (m *Migrator) run(ctx context.Context, migration Migration) error {
	m.logger.Info(
		"Running migration",
		slog.Uint64("version", migration.Version),
		slog.Any("direction", migration.Direction),
		slog.String("description", migration.Description),
	)

	stmts := m.driver.Parser()(migration.Content)

	err := m.driver.Execute(ctx, Script{
		Version:    migration.Version,
		Direction:  migration.Direction,
		Checksum:   migration.Checksum,
		Statements: stmts,
		Tx:         migration.Tx,
	})
	if err != nil {
		err = fmt.Errorf("migration %d failed: %w", migration.Version, err)
		m.logger.Error("Migration failed", slog.Any("error", err))
		return err
	}

	m.logger.Info(
		"Migration completed",
		slog.Uint64("version", migration.Version),
	)
	return nil
}

// load loads applied records and available files, ensuring that there are no
// missing files or checksum mismatches for previously applied migrations.
func (m *Migrator) load(ctx context.Context) ([]Record, []Migration, error) {
	// Fetch and strictly sort files
	files, err := m.files()
	if err != nil {
		return nil, nil, err
	}

	applied, err := m.driver.Applied(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get applied versions: %w", err)
	}

	ups := make(map[uint64]Migration)
	for _, f := range files {
		if f.Direction == Up {
			ups[f.Version] = f
		}
	}

	for _, a := range applied {
		if a.Dirty {
			return nil, nil, fmt.Errorf(
				"database is dirty at version %d; manual intervention required",
				a.Version,
			)
		}
		f, ok := ups[a.Version]
		if !ok {
			return nil, nil, fmt.Errorf(
				"applied migration %d is missing from source files",
				a.Version,
			)
		}
		if a.Checksum != f.Checksum {
			return nil, nil, fmt.Errorf(
				"checksum mismatch for migration %d: database has %x, file has %x",
				a.Version,
				a.Checksum,
				f.Checksum,
			)
		}
	}

	return applied, files, nil
}

// toLookup converts a slice of migration records to a map for quick lookups.
func toLookup(records []Record) map[uint64]bool {
	applied := make(map[uint64]bool, len(records))
	for _, r := range records {
		applied[r.Version] = true
	}
	return applied
}
