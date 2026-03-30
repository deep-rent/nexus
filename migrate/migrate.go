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
// migrations. It manages the loading, sorting, verification, and execution
// of migration files against a database driver.
//
// Example usage:
//
//	src := file.New(os.DirFS("./migrations"))
//	drv, err := postgres.New(db)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	m := migrate.New(
//	    migrate.WithSource(src),
//	    migrate.WithDriver(drv),
//	)
//
//	if err := m.Up(context.Background()); err != nil {
//	    log.Fatal("Migration failed:", err)
//	}
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

// Direction signals whether a migration is being applied or reverted.
type Direction int

const (
	// Up indicates a migration that applies changes to the database schema.
	Up Direction = iota
	// Down indicates a migration that undoes changes made by an Up migration.
	Down
)

// String implements the fmt.Stringer interface.
func (d Direction) String() string {
	switch d {
	case Up:
		return "up"
	case Down:
		return "down"
	default:
		return "unknown"
	}
}

// Record represents a successfully applied migration stored in the database.
type Record struct {
	// Version is the unique sequence number of the applied migration.
	Version uint64
	// Checksum is the SHA-256 hash of the migration's content, used to detect
	// tampering or accidental modification of historical migration files.
	Checksum [32]byte
	// Dirty indicates if the migration failed mid-execution, leaving the
	// database in a potentially inconsistent state that requires manual
	// intervention.
	Dirty bool
}

// Driver is the interface that database-specific backends must implement.
// It abstracts all direct database interactions, locking mechanisms, and
// state tracking away from the core migration logic.
type Driver interface {
	// Parser returns a database-specific statement parser to safely split
	// raw SQL scripts into individual executable statements.
	Parser() schema.Parser
	// Init ensures the migration tracking table exists in the database.
	Init(ctx context.Context) error
	// Lock acquires an exclusive, distributed lock to prevent concurrent
	// migrator instances from causing race conditions.
	Lock(ctx context.Context) error
	// Unlock releases the exclusive distributed lock.
	Unlock(ctx context.Context) error
	// Applied returns all successfully applied migration records from the
	// tracking table, ordered by version in ascending order.
	Applied(ctx context.Context) ([]Record, error)
	// Force sets the database to the specified version and clears the dirty
	// state, effectively ignoring any migrations past that point.
	Force(ctx context.Context, version uint64) error
	// Execute runs the parsed migration statements and records the state update
	// within the tracking table.
	Execute(ctx context.Context, script ParsedScript) error
	// Close cleans up driver resources and closes database connections.
	Close() error
}

// Source provides migrations from an external system (e.g., filesystem).
type Source interface {
	// List returns a list of all available migration files.
	// The Migrator will handle hashing the content and sorting the results.
	List() ([]SourceScript, error)
}

// SourceScript represents an unhashed migration script retrieved from a Source.
type SourceScript struct {
	// Version is the unique sequence number of the migration.
	Version uint64
	// Description is a human-readable summary of the migration's intent.
	Description string
	// Direction indicates whether this script applies (Up) or reverts (Down)
	// changes.
	Direction Direction
	// Path is the location identifier of the script within the source.
	Path string
	// Content contains the raw, unparsed SQL script.
	Content []byte
	// Tx specifies whether the script should be executed within a transaction.
	Tx bool
}

// ParsedScript holds the parameters required to execute a migration.
type ParsedScript struct {
	// Version is the unique sequence number of the migration.
	Version uint64
	// Direction indicates whether this script applies (Up) or reverts (Down)
	// changes.
	Direction Direction
	// Checksum is the cryptographic hash of the original script content.
	Checksum [32]byte
	// Statements contains the individually parsed SQL statements ready for
	// execution.
	Statements []string
	// Tx specifies whether the statements should be executed within a
	// transaction.
	Tx bool
}

// Migration represents a fully parsed and hashed migration file.
type Migration struct {
	// Version is the unique sequence number of the migration.
	Version uint64
	// Description is a human-readable description of the migration.
	Description string
	// Direction indicates whether this script applies (Up) or reverts (Down)
	// changes.
	Direction Direction
	// Path is the location identifier of the script within the source from which
	// the migration stems.
	Path string
	// Checksum is the SHA-256 hash of the content.
	Checksum [32]byte
	// Content is the raw SQL content of the migration, which can contain multiple
	// statements.
	Content []byte
	// Tx indicates whether to run all statements together in a transaction.
	Tx bool
}

// Compare returns an integer comparing two migrations to establish a strict
// ordering. The result will be 0 if m == other, -1 if m < other, and +1 if
// m > other.
//
// Migrations are ordered primarily by version in ascending order. If two
// migrations share the same version, they are secondarily ordered by direction
// (so "up" comes before "down") to guarantee deterministic sorting.
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
	dryRun bool // Determines if execution should be skipped
	logger *slog.Logger
}

// Option configures a Migrator instance.
type Option func(*Migrator)

// WithSource sets the migration source.
// This option is mandatory.
func WithSource(source Source) Option {
	return func(m *Migrator) {
		m.source = source
	}
}

// WithDriver sets the database driver.
// This option is mandatory.
func WithDriver(driver Driver) Option {
	return func(m *Migrator) {
		m.driver = driver
	}
}

// WithDryRun enables a mode where the Migrator computes the checksums and
// logs the parsed statements without executing them against the database.
func WithDryRun(enabled bool) Option {
	return func(m *Migrator) {
		m.dryRun = enabled
	}
}

// WithLogger sets the logger for the migrator.
// A nil value will be ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(m *Migrator) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// New creates a new Migrator instance. It panics if the required dependencies
// (Source and Driver) are not provided.
func New(opts ...Option) *Migrator {
	m := &Migrator{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.source == nil {
		panic("migrate: source is required")
	}
	if m.driver == nil {
		panic("migrate: driver is required")
	}
	return m
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
// cryptographic checksums, maps them to domain objects, and strictly sorts
// them.
func (m *Migrator) files() ([]Migration, error) {
	files, err := m.source.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list source files: %w", err)
	}

	migrations := make([]Migration, 0, len(files))
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

// filter is a helper to fetch either pending or applied migrations.
func (m *Migrator) filter(ctx context.Context, up bool) ([]Migration, error) {
	records, files, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	applied := toLookup(records)

	out := make([]Migration, 0, len(files))
	for _, f := range files {
		if f.Direction == Up && applied[f.Version] == up {
			out = append(out, f)
		}
	}
	return out, nil
}

// Up applies all pending migrations in ascending order.
func (m *Migrator) Up(ctx context.Context) error {
	return m.lock(ctx, m.up)
}

func (m *Migrator) up(ctx context.Context) error {
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
}

// Down reverts the most recently applied migration.
func (m *Migrator) Down(ctx context.Context) error {
	return m.lock(ctx, m.down)
}

func (m *Migrator) down(ctx context.Context) error {
	applied, err := m.Applied(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		m.logger.Info("No applied migrations to revert")
		return nil
	}

	// Get the last applied migration to revert.
	last := applied[len(applied)-1]

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
}

// Force manually sets the database to the specified version and clears the
// dirty flag. It should be used to resolve a dirty state after human
// intervention.
func (m *Migrator) Force(ctx context.Context, version uint64) error {
	fn := func(c context.Context) error {
		if err := m.driver.Force(c, version); err != nil {
			return fmt.Errorf("failed to force version: %w", err)
		}
		m.logger.Info(
			"Successfully forced migration version",
			slog.Uint64("version", version),
		)
		return nil
	}

	return m.lock(ctx, fn)
}

// MigrateTo applies or reverts migrations to reach the target version.
func (m *Migrator) MigrateTo(ctx context.Context, target uint64) error {
	fn := func(c context.Context) error {
		records, files, err := m.load(c)
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
						if err := m.run(c, f); err != nil {
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
				if err := m.run(c, f); err != nil {
					return err
				}
				applied[f.Version] = true
			}
		}

		return nil
	}

	return m.lock(ctx, fn)
}

// Pending returns a list of "Up" migrations that have not yet been applied.
func (m *Migrator) Pending(ctx context.Context) ([]Migration, error) {
	return m.filter(ctx, false)
}

// Applied returns a list of "Up" migrations that have already been executed.
func (m *Migrator) Applied(ctx context.Context) ([]Migration, error) {
	return m.filter(ctx, true)
}

// run reads the migration payload and executes it via the driver.
// If dry run is enabled, it logs the statements and skips execution.
func (m *Migrator) run(ctx context.Context, migration Migration) error {
	m.logger.Info(
		"Running migration",
		slog.Uint64("version", migration.Version),
		slog.String("description", migration.Description),
		slog.String("direction", migration.Direction.String()),
	)

	parse := m.driver.Parser()
	stmts := parse(migration.Content)

	if m.dryRun {
		m.logger.Info(
			"Dry run: skipping execution",
			slog.Int("statements", len(stmts)),
		)
		for i, stmt := range stmts {
			m.logger.Debug(
				"Dry run statement",
				slog.Int("index", i+1),
				slog.String("query", stmt),
			)
		}
		return nil
	}

	err := m.driver.Execute(ctx, ParsedScript{
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
	files, err := m.files()
	if err != nil {
		return nil, nil, err
	}

	applied, err := m.driver.Applied(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get applied versions: %w", err)
	}

	ups := make(map[uint64]Migration, len(files))
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
