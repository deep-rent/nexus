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

// Package file provides a file system-based source for database migrations.
//
// It implements the [migrate.Source] interface by reading migration scripts
// from any implementation of the standard library's [fs.FS] interface (such
// as [os.DirFS] or [embed.FS]). It parses filenames to extract the migration
// version, description, execution direction (up/down), and whether the
// migration should run inside a transaction.
//
// # Filename Format
//
// The expected filename format is:
//
//	<version>_<description>.<direction>[_notx]<extension>
//
// For example, "42_add_users.up.sql" describes version 42, applies changes
// ("up"), and runs inside a transaction. Its counterpart
// "42_add_users.down.sql" reverts it.
//
//   - <version> is a non-negative decimal integer. Leading zeros are
//     allowed and ignored ("007" equals "7"). Every version must be unique
//     per direction across the whole tree; duplicates are rejected by the
//     migrator.
//   - <description> must be non-empty. Underscores are replaced with
//     spaces ("add_users" becomes "add users").
//   - <direction> is the lowercase literal "up" or "down".
//   - The optional "_notx" suffix disables transactional execution for
//     scripts that contain statements that cannot run inside a transaction
//     (e.g. CREATE INDEX CONCURRENTLY).
//
// Matching is case-sensitive. The file system is scanned recursively;
// subdirectories carry no semantic meaning and only the base filename is
// parsed. Files that do not match the configured extension or the naming
// convention are skipped and logged at debug level.
//
// # Usage
//
// Initialize a source by providing a filesystem and optional configuration.
//
// Example:
//
//	// Using an embedded filesystem
//	//go:embed sql/*.sql
//	var fs embed.FS
//
//	src := file.New(fs, file.WithExtension(".sql"), file.WithLogger(logger))
//	migrations, err := src.List()
package file
