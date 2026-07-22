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
//
// It manages the loading, sorting, verification, and execution of migration
// files against a database driver. Migrations are applied in a consistent,
// reproducible order, and the state of the database is tracked to prevent
// duplicate or conflicting changes.
//
// # Usage
//
// To perform migrations, initialize a source and a driver, then create a new
// [Migrator].
//
// Example:
//
//	src := file.New(os.DirFS("./migrations"))
//	drv := postgres.New(db)
//
//	m := migrate.New(
//	    migrate.WithSource(src),
//	    migrate.WithDriver(drv),
//	)
//
//	if err := m.Up(context.Background()); err != nil {
//	    log.Fatal("Migration failed:", err)
//	}
//
// # Locking
//
// All mutating operations ([Migrator.Up], [Migrator.Down], [Migrator.Steps],
// [Migrator.MigrateTo], and [Migrator.Force]) acquire an exclusive,
// driver-provided distributed lock so that concurrent migrator instances
// cannot interleave. The read-only status queries ([Migrator.Pending],
// [Migrator.Applied], and [Migrator.Version]) do not lock; they provide a
// consistent snapshot but no protection against a migration running at the
// same time.
//
// # Dirty State and Recovery
//
// Before a migration executes, its version is recorded as dirty; after
// successful completion the flag is cleared. A migration that fails without
// transactional protection leaves the record dirty, and every subsequent
// operation refuses to proceed until the database has been inspected.
// After manually restoring a consistent state, use [Migrator.Force] to set
// the version and clear the flag. [Migrator.Version] can inspect the current
// (possibly dirty) state at any time.
//
// # Integrity
//
// The SHA-256 checksum of every applied "up" migration is stored in the
// tracking table and verified on each run, so historical migration files
// cannot change unnoticed. Down scripts are not checksummed: they only run
// when explicitly requested, and no reference hash exists once the record
// has been removed. Review down scripts before reverting.
package migrate
