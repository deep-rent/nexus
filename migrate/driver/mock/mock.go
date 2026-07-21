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

package mock

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/schema"
)

// Driver is an in-memory implementation of [migrate.Driver].
//
// It is safe for concurrent use and allows injecting errors for every operation
// to test the Migrator's error handling and rollback logic.
type Driver struct {
	// mu protects the internal state of the mock driver.
	mu sync.Mutex
	// records stores the simulated migration state.
	records map[int64]migrate.Record

	// IsLocked indicates if the mock advisory lock is currently held.
	IsLocked bool
	// IsInit indicates if the tracking table initialization was called.
	IsInit bool

	// ParserFunc allows injecting a custom statement parser.
	ParserFunc schema.Parser

	// InitErr is returned by the Init method if non-nil.
	InitErr error
	// LockErr is returned by the Lock method if non-nil.
	LockErr error
	// UnlockErr is returned by the Unlock method if non-nil.
	UnlockErr error
	// AppliedErr is returned by the Applied method if non-nil.
	AppliedErr error
	// ForceErr is returned by the Force method if non-nil.
	ForceErr error
	// ExecuteErr is returned by the Execute method if non-nil.
	ExecuteErr error
}

// New creates a new in-memory [Driver] with an empty state.
func New() *Driver {
	return &Driver{
		records: make(map[int64]migrate.Record),
		// Provide a dummy parser that just returns the raw script as a single
		// statement.
		ParserFunc: func(script []byte) []string {
			if len(script) == 0 {
				return nil
			}
			return []string{string(script)}
		},
	}
}

// Set writes a [migrate.Record] to the in-memory table.
func (d *Driver) Set(rec migrate.Record) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[rec.Version] = rec
}

// Get reads a [migrate.Record] from the in-memory table.
func (d *Driver) Get(version int64) (migrate.Record, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec, ok := d.records[version]
	return rec, ok
}

// State returns a copy of the in-memory table.
func (d *Driver) State() map[int64]migrate.Record {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[int64]migrate.Record, len(d.records))
	maps.Copy(out, d.records)
	return out
}

// Parser returns the injected [Driver.ParserFunc].
func (d *Driver) Parser() schema.Parser {
	return d.ParserFunc
}

// Init simulates creating the tracking table.
func (d *Driver) Init(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.InitErr != nil {
		return d.InitErr
	}
	d.IsInit = true
	return nil
}

// Lock simulates acquiring an exclusive distributed lock.
func (d *Driver) Lock(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.LockErr != nil {
		return d.LockErr
	}
	if d.IsLocked {
		return errors.New("already locked")
	}

	d.IsLocked = true
	return nil
}

// Unlock simulates releasing the exclusive lock.
func (d *Driver) Unlock(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.UnlockErr != nil {
		return d.UnlockErr
	}
	if !d.IsLocked {
		return errors.New("not locked")
	}

	d.IsLocked = false
	return nil
}

// Applied returns all successfully applied migration records, sorted by
// version.
func (d *Driver) Applied(ctx context.Context) ([]migrate.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.AppliedErr != nil {
		return nil, d.AppliedErr
	}

	out := make([]migrate.Record, 0, len(d.records))
	for _, r := range d.records {
		out = append(out, r)
	}

	slices.SortFunc(out, func(a, b migrate.Record) int {
		return cmp.Compare(a.Version, b.Version)
	})

	return out, nil
}

// Force manually sets the database version.
//
// It clears the dirty flag for that version and removes any records greater
// than it.
func (d *Driver) Force(ctx context.Context, version int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.ForceErr != nil {
		return d.ForceErr
	}

	if rec, ok := d.records[version]; ok {
		rec.Dirty = false
		d.records[version] = rec
	}

	for v := range d.records {
		if v > version {
			delete(d.records, v)
		}
	}

	return nil
}

// Execute simulates running a migration script.
//
// If [Driver.ExecuteErr] is set, it simulates a failure: transactional
// scripts roll back cleanly and leave no dirty state, while
// non-transactional scripts leave the target version dirty, mirroring the
// behavior of real drivers.
func (d *Driver) Execute(
	ctx context.Context,
	script migrate.ParsedScript,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.ExecuteErr != nil {
		if script.Tx {
			// A failed transactional migration rolls back and removes its
			// dirty marker again.
			return d.ExecuteErr
		}
		// Simulate the dirty state left behind by a failed non-transactional
		// migration.
		switch script.Direction {
		case migrate.Up:
			d.records[script.Version] = migrate.Record{
				Version:  script.Version,
				Checksum: script.Checksum,
				Dirty:    true,
			}
		case migrate.Down:
			if rec, ok := d.records[script.Version]; ok {
				rec.Dirty = true
				d.records[script.Version] = rec
			}
		}
		return d.ExecuteErr
	}

	// Simulate successful execution.
	switch script.Direction {
	case migrate.Up:
		d.records[script.Version] = migrate.Record{
			Version:  script.Version,
			Checksum: script.Checksum,
			Dirty:    false,
		}
	case migrate.Down:
		delete(d.records, script.Version)
	}

	return nil
}

var _ migrate.Driver = (*Driver)(nil)
