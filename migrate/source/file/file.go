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
// It implements the migrate.Source interface by reading migration scripts
// from any implementation of the standard library's fs.FS interface (such
// as os.DirFS or embed.FS). It parses filenames to extract the migration
// version, description, execution direction (up/down), and whether the
// migration should run inside a transaction.
//
// The expected filename format is:
//
//	<version>_<description>.<direction>[_notx]<extension>
//
// Examples of valid filenames:
//   - 00001_create_users_table.up.sql
//   - 00001_create_users_table.down.sql
//   - 00002_add_concurrent_index.up_notx.sql
package file

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/deep-rent/nexus/migrate"
)

const (
	// DefaultExtension is the default file extension used when searching for
	// migration scripts in the file system.
	DefaultExtension = ".sql"
)

// config holds the internal configuration options for the file source.
type config struct {
	ext string
}

// Option configures a Source instance.
type Option func(*config)

// WithExtension sets a custom file extension for migration files.
// It automatically prepends a leading dot if one is missing.
// Empty string values are ignored.
func WithExtension(ext string) Option {
	return func(c *config) {
		if ext == "" {
			return
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		c.ext = ext
	}
}

// Source implements the migrate.Source interface for an fs.FS.
// It scans the file system to discover, parse, and hash migration files.
type Source struct {
	dir fs.FS  // The file system containing the migration scripts.
	ext string // The file extension used to filter relevant scripts.
}

// New creates a new Source instance that reads from the provided fs.FS.
// Options can be provided to customize behavior, such as changing the
// expected file extension.
func New(dir fs.FS, opts ...Option) *Source {
	cfg := &config{
		ext: DefaultExtension,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return &Source{
		dir: dir,
		ext: cfg.ext,
	}
}

// List reads the underlying file system, parses all files matching the
// configured extension, calculates their SHA-256 checksums, and returns
// a complete list of valid migrations.
//
// The returned slice is strictly sorted by Version in ascending order.
// If multiple files share the same version (e.g., an 'up' and a 'down' file),
// they are secondarily sorted by Direction to ensure deterministic output.
func (s *Source) List() ([]migrate.Migration, error) {
	var migrations []migrate.Migration

	err := fs.WalkDir(s.dir, ".", func(
		path string,
		d fs.DirEntry,
		err error,
	) error {
		if err != nil || d.IsDir() {
			return err
		}

		name := d.Name()
		version, desc, direction, tx, ok := s.parse(name)
		if !ok {
			return nil // Skip files that don't match the expected migration format
		}

		content, err := fs.ReadFile(s.dir, path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", path, err)
		}

		// Calculate the SHA-256 checksum of the raw file content to ensure
		// integrity during future migration runs.
		hash := sha256.Sum256(content)

		migrations = append(migrations, migrate.Migration{
			Version:     version,
			Description: desc,
			Direction:   direction,
			Path:        path,
			Checksum:    hash,
			Content:     content,
			Tx:          tx,
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read migration directory: %w", err)
	}

	slices.SortFunc(migrations, migrate.Migration.Compare)
	return migrations, nil
}

// parse attempts to extract migration details from a filename.
//
// Expected format: <version>_<description>.<direction>[_notx]<extension>
//
// Returns ok=false if the filename does not match the strict format, allowing
// the caller to gracefully skip unrelated files (like READMEs or local config).
func (s *Source) parse(name string) (
	version uint64,
	desc string,
	direction migrate.Direction,
	tx bool,
	ok bool,
) {
	tx = true // Migrations run inside a transaction by default
	base, found := strings.CutSuffix(name, s.ext)
	if !found {
		return 0, "", "", false, false
	}

	// Split the direction segment from the rest of the base name.
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return 0, "", "", false, false // Missing period
	}

	s2 := base[dot+1:]

	// Check if transactional execution was explicitly disabled via the
	// _notx suffix.
	if disabled, found := strings.CutSuffix(s2, "_notx"); found {
		tx = false
		s2 = disabled
	}

	// Validate the direction.
	switch s2 {
	case string(migrate.Up):
		direction = migrate.Up
	case string(migrate.Down):
		direction = migrate.Down
	default:
		return 0, "", "", false, false // Illegal direction
	}

	base = base[:dot]

	// Split the version from the description.
	// Cut splits at the *first* instance of the separator, allowing descriptions
	// to safely contain additional underscores.
	s0, s1, found := strings.Cut(base, "_")
	if !found {
		return 0, "", "", false, false // Missing underscore
	}
	if s0 == "" || s1 == "" {
		return 0, "", "", false, false // Empty version or description
	}

	// Parse the version string into an unsigned integer.
	v, err := strconv.ParseUint(s0, 10, 64)
	if err != nil {
		return 0, "", "", false, false // Version is not numeric
	}

	version = v

	// Finalize the description by converting remaining underscores to spaces
	// to make it human-readable for logging.
	desc = strings.ReplaceAll(s1, "_", " ")

	return version, desc, direction, tx, true
}
