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

// Source implements migrate.Source for a standard fs.FS.
type Source struct {
	fs fs.FS
}

// New creates a new Source instance.
func New(fs fs.FS) *Source {
	return &Source{fs: fs}
}

// List reads and validates the fs.FS, returning sorted migrations.
func (s *Source) List() ([]migrate.Migration, error) {
	var migrations []migrate.Migration

	err := fs.WalkDir(s.fs, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		name := d.Name()
		version, desc, direction, ok := parseFilename(name)
		if !ok {
			return nil // Skip files that don't match the migration format
		}

		payload, err := fs.ReadFile(s.fs, p)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", p, err)
		}
		hash := sha256.Sum256(payload)

		migrations = append(migrations, migrate.Migration{
			Version:     version,
			Description: desc,
			Direction:   direction,
			Path:        p,
			Checksum:    hash[:],
			Content:     payload,
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

// parseFilename extracts migration details from a filename.
// Expected format: <version>_<description>.<direction>.sql
func parseFilename(name string) (version uint64, description string, direction migrate.Direction, ok bool) {
	if !strings.HasSuffix(name, ".sql") {
		return 0, "", "", false
	}

	parts := strings.Split(name[:len(name)-4], ".")
	if len(parts) != 2 {
		return 0, "", "", false
	}

	dirStr := parts[1]
	if dirStr != string(migrate.Up) && dirStr != string(migrate.Down) {
		return 0, "", "", false
	}
	direction = migrate.Direction(dirStr)

	baseParts := strings.SplitN(parts[0], "_", 2)
	if len(baseParts) < 1 {
		return 0, "", "", false
	}

	v, err := strconv.ParseUint(baseParts[0], 10, 64)
	if err != nil {
		return 0, "", "", false
	}
	version = v

	if len(baseParts) > 1 {
		description = strings.ReplaceAll(baseParts[1], "_", " ")
	}
	return version, description, direction, true
}
