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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
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
	Checksum string
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
	// Force sets the database to the specified version and clears the dirty state.
	Force(ctx context.Context, version uint64) error
	// Execute runs the migration statements and updates the tracking table.
	// If useTx is true, all statements should be executed within a single transaction.
	Execute(
		ctx context.Context,
		version uint64,
		direction Direction,
		checksum string,
		statements []string,
		useTx bool,
	) error
	// Close cleans up driver resources.
	Close() error
}

// Migration represents a parsed migration file.
type Migration struct {
	Version     uint64
	Description string
	Direction   Direction
	Path        string // Path in the fs.FS
	Checksum    string // SHA-256 hash of the file contents
}

// Migrator orchestrates the execution of database migrations.
type Migrator struct {
	src    fs.FS
	driver Driver
}

// New creates a new Migrator instance.
func New(src fs.FS, driver Driver) *Migrator {
	return &Migrator{
		src:    src,
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
	allFiles, err := m.parseFiles()
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

// Force manually sets the database to the specified version and clears the dirty
// flag. It should be used to resolve a dirty state after human intervention.
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
func (m *Migrator) MigrateTo(ctx context.Context, targetVersion uint64) error {
	if err := m.driver.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = m.driver.Unlock(context.Background())
	}()

	if err := m.driver.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize driver: %w", err)
	}

	appliedVersions, allFiles, err := m.loadAndValidate(ctx)
	if err != nil {
		return err
	}

	appliedMap := make(map[uint64]bool, len(appliedVersions))
	for _, v := range appliedVersions {
		appliedMap[v.Version] = true
	}

	// Revert applied migrations strictly greater than targetVersion in descending
	// order.
	for i := len(appliedVersions) - 1; i >= 0; i-- {
		v := appliedVersions[i].Version
		if v > targetVersion {
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

	// Apply pending migrations less than or equal to targetVersion in ascending
	// order.
	for _, f := range allFiles {
		if f.Direction == Up &&
			f.Version <= targetVersion &&
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
	appliedVersions, allFiles, err := m.loadAndValidate(ctx)
	if err != nil {
		return nil, err
	}

	appliedMap := make(map[uint64]bool, len(appliedVersions))
	for _, v := range appliedVersions {
		appliedMap[v.Version] = true
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
	appliedVersions, allFiles, err := m.loadAndValidate(ctx)
	if err != nil {
		return nil, err
	}

	appliedMap := make(map[uint64]bool, len(appliedVersions))
	for _, v := range appliedVersions {
		appliedMap[v.Version] = true
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
	payload, err := fs.ReadFile(m.src, migration.Path)
	if err != nil {
		return fmt.Errorf(
			"failed to read migration file %s: %w",
			migration.Path,
			err,
		)
	}

	payloadStr := string(payload)
	useTx := !strings.Contains(payloadStr, "-- nexus:no-tx") && !strings.Contains(payloadStr, "-- no-transaction")
	statements := m.driver.Parser()(payloadStr)

	err = m.driver.Execute(
		ctx,
		migration.Version,
		migration.Direction,
		migration.Checksum,
		statements,
		useTx,
	)
	if err != nil {
		return fmt.Errorf(
			"migration %d failed: %w",
			migration.Version,
			err,
		)
	}

	return nil
}

// parseFiles reads and validates the fs.FS, returning sorted migrations.
func (m *Migrator) parseFiles() ([]Migration, error) {
	var migrations []Migration

	err := fs.WalkDir(m.src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		name := d.Name()
		if !strings.HasSuffix(name, ".sql") {
			return nil // Skip non-SQL files
		}

		// Expected format: <version>_<description>.<direction>.sql
		parts := strings.Split(name, ".")
		if len(parts) != 3 {
			return fmt.Errorf("invalid migration file format: %s", name)
		}

		directionStr := parts[1]
		if directionStr != string(Up) && directionStr != string(Down) {
			return fmt.Errorf("invalid direction %q in file: %s", directionStr, name)
		}

		baseParts := strings.SplitN(parts[0], "_", 2)
		if len(baseParts) < 1 {
			return fmt.Errorf("missing version in file: %s", name)
		}

		version, err := strconv.ParseUint(baseParts[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid version %q in file: %s", baseParts[0], name)
		}

		desc := ""
		if len(baseParts) > 1 {
			desc = baseParts[1]
		}

		payload, err := fs.ReadFile(m.src, p)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", p, err)
		}
		hash := sha256.Sum256(payload)
		checksum := hex.EncodeToString(hash[:])

		migrations = append(migrations, Migration{
			Version:     version,
			Description: desc,
			Direction:   Direction(directionStr),
			Path:        p,
			Checksum:    checksum,
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read migration directory: %w", err)
	}

	// Sort mathematically by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// loadAndValidate reads applied records and available files, ensuring that
// there are no missing files or checksum mismatches for previously applied
// migrations.
func (m *Migrator) loadAndValidate(ctx context.Context) ([]Record, []Migration, error) {
	allFiles, err := m.parseFiles()
	if err != nil {
		return nil, nil, err
	}

	appliedVersions, err := m.driver.Applied(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get applied versions: %w", err)
	}

	upFiles := make(map[uint64]Migration)
	for _, f := range allFiles {
		if f.Direction == Up {
			upFiles[f.Version] = f
		}
	}

	for _, a := range appliedVersions {
		if a.Dirty {
			return nil, nil, fmt.Errorf("database is dirty at version %d; manual intervention required", a.Version)
		}
		f, ok := upFiles[a.Version]
		if !ok {
			return nil, nil, fmt.Errorf("applied migration %d is missing from source files", a.Version)
		}
		// Accepts an empty checksum string in DB rows to safely handle backward compatibility.
		if a.Checksum != "" && a.Checksum != f.Checksum {
			return nil, nil, fmt.Errorf("checksum mismatch for migration %d: database has %s, file has %s", a.Version, a.Checksum, f.Checksum)
		}
	}

	return appliedVersions, allFiles, nil
}
