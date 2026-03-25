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

package migrate

import (
	"bytes"
	"context"
	"fmt"
	"strings"

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
	Checksum []byte
	Dirty    bool
}

// Driver is the interface that database-specific backends must implement.
type Driver interface {
	// Parser returns a database-specific statement parser.
	Parser() schema.Parser
	// Init ensures the migration tracking table exists.
	Init(ctx context.Context) error
	// Lock acquires an exclusive lock to prevent concurrent migrations.
	Lock(ctx context.Context) error
	// Unlock releases the exclusive lock.
	Unlock(ctx context.Context) error
	// Applied returns all successfully applied migration records in ascending
	// order.
	Applied(ctx context.Context) ([]Record, error)
	// Force sets the database to the specified version and clears the dirty
	// state.
	Force(ctx context.Context, version uint64) error
	// Execute runs the migration statements and updates the tracking table.
	// The behavior of the execution is dictated by the provided ExecuteParams.
	Execute(ctx context.Context, script Script) error
	// Close cleans up driver resources.
	Close() error
}

// Source provides migrations.
type Source interface {
	// ListMigrations returns a list of all available migrations, sorted by version.
	// The implementation is responsible for reading migration files and calculating
	// their checksums.
	ListMigrations() ([]Migration, error)
}

// Script holds the parameters required to execute a migration.
type Script struct {
	Version    uint64
	Direction  Direction
	Checksum   []byte
	Statements []string
	Tx         bool
}

// Migration represents a parsed migration file.
type Migration struct {
	Version     uint64
	Description string
	Direction   Direction
	Path        string // Path in the fs.FS
	Checksum    []byte // SHA-256 hash of the content
	Content     []byte // Raw file content
}

// Migrator orchestrates the execution of database migrations.
type Migrator struct {
	source Source
	driver Driver
}

// New creates a new Migrator instance.
func New(source Source, driver Driver) *Migrator {
	return &Migrator{
		source: source,
		driver: driver,
	}
}

// Up applies all pending migrations in ascending order.
func (m *Migrator) Up(ctx context.Context) error {
	if err := m.driver.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = m.driver.Unlock(context.Background())
	}()

	if err := m.driver.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize driver: %w", err)
	}

	pending, err := m.Pending(ctx)
	if err != nil {
		return err
	}

	for _, p := range pending {
		if err := m.run(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// Down reverts the most recently applied migration.
func (m *Migrator) Down(ctx context.Context) error {
	if err := m.driver.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = m.driver.Unlock(context.Background())
	}()

	if err := m.driver.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize driver: %w", err)
	}

	appliedMigrations, err := m.Applied(ctx)
	if err != nil || len(appliedMigrations) == 0 {
		return err // Either an error or nothing to revert
	}

	// Get the last applied migration to revert
	lastApplied := appliedMigrations[len(appliedMigrations)-1]

	// We need the corresponding 'down' file for this version
	allFiles, err := m.source.ListMigrations()
	if err != nil {
		return err
	}

	for _, f := range allFiles {
		if f.Version == lastApplied.Version && f.Direction == Down {
			return m.run(ctx, f)
		}
	}

	return fmt.Errorf(
		"down migration file not found for version %d",
		lastApplied.Version,
	)
}

// Force manually sets the database to the specified version and clears the
// dirty flag. It should be used to resolve a dirty state after human
// intervention.
func (m *Migrator) Force(ctx context.Context, version uint64) error {
	if err := m.driver.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = m.driver.Unlock(context.Background())
	}()

	if err := m.driver.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize driver: %w", err)
	}

	if err := m.driver.Force(ctx, version); err != nil {
		return fmt.Errorf("failed to force version: %w", err)
	}

	return nil
}

// MigrateTo applies or reverts migrations to reach the target version.
func (m *Migrator) MigrateTo(ctx context.Context, target uint64) error {
	if err := m.driver.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = m.driver.Unlock(context.Background())
	}()

	if err := m.driver.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize driver: %w", err)
	}

	appliedVersions, appliedMap, allFiles, err := m.load(ctx)
	if err != nil {
		return err
	}

	// Revert applied migrations strictly greater than the target version in
	// descending order.
	for i := len(appliedVersions) - 1; i >= 0; i-- {
		v := appliedVersions[i].Version
		if v > target {
			found := false
			for _, f := range allFiles {
				if f.Version == v && f.Direction == Down {
					if err := m.run(ctx, f); err != nil {
						return err
					}
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf(
					"down migration file not found for version %d",
					v,
				)
			}
			appliedMap[v] = false
		}
	}

	// Apply pending migrations less than or equal to the target version in
	// ascending order.
	for _, f := range allFiles {
		if f.Direction == Up &&
			f.Version <= target &&
			!appliedMap[f.Version] {
			if err := m.run(ctx, f); err != nil {
				return err
			}
			appliedMap[f.Version] = true
		}
	}

	return nil
}

// Pending returns a list of "Up" migrations that have not yet been applied.
func (m *Migrator) Pending(ctx context.Context) ([]Migration, error) {
	_, appliedMap, allFiles, err := m.load(ctx)
	if err != nil {
		return nil, err
	}

	var pending []Migration
	for _, f := range allFiles {
		if f.Direction == Up && !appliedMap[f.Version] {
			pending = append(pending, f)
		}
	}

	return pending, nil
}

// Applied returns a list of "Up" migrations that have already been executed.
func (m *Migrator) Applied(ctx context.Context) ([]Migration, error) {
	_, appliedMap, allFiles, err := m.load(ctx)
	if err != nil {
		return nil, err
	}

	var applied []Migration
	for _, f := range allFiles {
		if f.Direction == Up && appliedMap[f.Version] {
			applied = append(applied, f)
		}
	}

	return applied, nil
}

// run reads the migration payload and executes it via the driver.
func (m *Migrator) run(ctx context.Context, migration Migration) error {
	payloadStr := string(migration.Content)
	useTx := !strings.Contains(payloadStr, "-- nexus:no-tx")
	statements := m.driver.Parser()(payloadStr)

	err := m.driver.Execute(ctx, Script{
		Version:    migration.Version,
		Direction:  migration.Direction,
		Checksum:   migration.Checksum,
		Statements: statements,
		Tx:         useTx,
	})
	if err != nil {
		return fmt.Errorf(
			"migration %d failed: %w",
			migration.Version,
			err,
		)
	}

	return nil
}

// load loads applied records and available files, ensuring that there are no
// missing files or checksum mismatches for previously applied migrations.
func (m *Migrator) load(ctx context.Context) ([]Record, map[uint64]bool, []Migration, error) {
	allFiles, err := m.source.ListMigrations()
	if err != nil {
		return nil, nil, nil, err
	}

	appliedVersions, err := m.driver.Applied(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get applied versions: %w", err)
	}

	appliedMap := make(map[uint64]bool, len(appliedVersions))
	for _, a := range appliedVersions {
		appliedMap[a.Version] = true
	}

	upFiles := make(map[uint64]Migration)
	for _, f := range allFiles {
		if f.Direction == Up {
			upFiles[f.Version] = f
		}
	}

	for _, a := range appliedVersions {
		if a.Dirty {
			return nil, nil, nil, fmt.Errorf(
				"database is dirty at version %d; manual intervention required",
				a.Version,
			)
		}
		f, ok := upFiles[a.Version]
		if !ok {
			return nil, nil, nil, fmt.Errorf(
				"applied migration %d is missing from source files",
				a.Version,
			)
		}
		// Accepts an empty checksum slice in DB rows to safely handle backward
		// compatibility.
		if len(a.Checksum) > 0 && !bytes.Equal(a.Checksum, f.Checksum) {
			return nil, nil, nil, fmt.Errorf(
				"checksum mismatch for migration %d: database has %x, file has %x",
				a.Version,
				a.Checksum,
				f.Checksum,
			)
		}
	}

	return appliedVersions, appliedMap, allFiles, nil
}
