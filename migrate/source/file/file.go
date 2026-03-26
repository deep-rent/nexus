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

package file

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/deep-rent/nexus/migrate"
)

const DefaultExtension = ".sql"

// Source implements migrate.Source for a standard fs.FS.
type Source struct {
	dir fs.FS
	ext string
}

// Option configures a Source.
type Option func(*Source)

// WithExtension sets the file extension for migration files.
// The default is ".sql". It automatically adds a leading dot if missing.
func WithExtension(ext string) Option {
	return func(s *Source) {
		if ext == "" {
			return
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		s.ext = ext
	}
}

// New creates a new Source instance.
func New(dir fs.FS, opts ...Option) *Source {
	s := &Source{
		dir: dir,
		ext: DefaultExtension,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// List reads and validates the fs.FS, returning sorted migrations.
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
			return nil // Skip files that don't match the migration format
		}

		content, err := fs.ReadFile(s.dir, path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", path, err)
		}

		// Calculate the file checksum.
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

	// Sort by version in ascending order (old to new).
	sort.Slice(migrations, func(i, j int) bool {
		m1 := migrations[i]
		m2 := migrations[j]
		return m1.Version < m2.Version
	})

	return migrations, nil
}

// parse extracts migration details from a filename.
// Expected format: <version>_<description>.<direction>.sql
func (s *Source) parse(name string) (
	version uint64,
	desc string,
	direction migrate.Direction,
	tx bool,
	ok bool,
) {
	tx = true // Default to using a transaction
	base, found := strings.CutSuffix(name, s.ext)
	if !found {
		return 0, "", "", false, false
	}

	// Split direction from the rest of the base name.
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return 0, "", "", false, false // Invalid format
	}
	base = base[:dot]

	// Validate the direction.
	switch base[dot+1:] {
	case string(migrate.Up):
		direction = migrate.Up
	case string(migrate.Down):
		direction = migrate.Down
	default:
		return 0, "", "", false, false // Illegal direction
	}

	// Optionally disable transactional execution.
	if base, found = strings.CutSuffix(base, "_notx"); found {
		tx = false
	}

	// Split version from description.
	vs, ds, found := strings.Cut(base, "_")
	if !found {
		return 0, "", "", false, false // Invalid format
	}
	if vs == "" || ds == "" {
		return 0, "", "", false, false // Empty version or description
	}

	// Parse the version number.
	v, err := strconv.ParseUint(vs, 10, 64)
	if err != nil {
		return 0, "", "", false, false // Version is not a number
	}

	version = v
	// Finalize the description.
	desc = strings.ReplaceAll(ds, "_", " ")

	return version, desc, direction, tx, true
}
