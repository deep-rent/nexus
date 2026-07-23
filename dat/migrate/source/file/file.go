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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/deep-rent/nexus/dat/migrate"
	"github.com/deep-rent/nexus/sys/log"
)

// Errors explaining why the [Source.Parse] method has failed:
var (
	// ErrExtension is returned when a filename does not end with the configured
	// file extension.
	ErrExtension = errors.New("extension mismatch")
	// ErrMissingDirection is returned when a filename lacks the dot separator
	// preceding the direction segment.
	ErrMissingDirection = errors.New("missing direction segment")
	// ErrIllegalDirection is returned when the direction segment is neither
	// "up" nor "down".
	ErrIllegalDirection = errors.New("illegal direction")
	// ErrMissingSeparator is returned when a filename lacks the underscore
	// separating the version from the description.
	ErrMissingSeparator = errors.New("missing underscore separator")
	// ErrInvalidDescription is returned when the description segment of the
	// filename is empty.
	ErrInvalidDescription = errors.New("invalid description")
	// ErrInvalidVersion is returned when the version segment is empty or cannot
	// be parsed into an unsigned integer.
	ErrInvalidVersion = errors.New("invalid version")
)

// Source implements the [migrate.Source] interface for an [fs.FS].
//
// It scans the file system to discover and parse migration files.
type Source struct {
	// dir is the filesystem containing the migration scripts.
	dir fs.FS
	// ext is the file extension used to filter relevant scripts.
	ext string
	// logger is the logger used for debugging missed conventions.
	logger *log.Logger
}

// New creates a new [Source] instance that reads from the provided [fs.FS].
//
// Options can be provided to customize behavior, such as changing the expected
// file extension.
func New(dir fs.FS, opts ...Option) *Source {
	cfg := &config{
		ext:    DefaultExtension,
		logger: log.Discard(),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return &Source{
		dir:    dir,
		ext:    cfg.ext,
		logger: cfg.logger,
	}
}

// Directory returns the underlying file system used by the source.
func (s *Source) Directory() fs.FS {
	return s.dir
}

// Extension returns the configured file extension used to identify
// migration scripts.
func (s *Source) Extension() string {
	return s.ext
}

// Parse extracts metadata from a given filename.
//
// It extracts the version, description, execution direction, and transaction
// flag. It returns an error if the filename does not match the strict
// <version>_<description>.<direction>[_notx]<extension> format.
func (s *Source) Parse(name string) (
	version int64,
	desc string,
	direction migrate.Direction,
	tx bool,
	err error,
) {
	// Default to transactional execution unless explicitly disabled.
	tx = true

	// Strip the configured file extension (e.g., ".sql").
	base, found := strings.CutSuffix(name, s.ext)
	if !found {
		return 0, "", 0, false, ErrExtension
	}

	// Locate the dot that separates the version/description from the direction.
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return 0, "", 0, false, ErrMissingDirection
	}

	// Extract the direction segment (e.g., "up", "down", or "up_notx").
	s2 := base[dot+1:]

	// Check for the "_notx" suffix to determine if transactions should be
	// disabled.
	if disabled, found := strings.CutSuffix(s2, "_notx"); found {
		tx = false
		s2 = disabled
	}

	// Map the direction string to the internal direction type.
	switch s2 {
	case "up":
		direction = migrate.Up
	case "down":
		direction = migrate.Down
	default:
		return 0, "", 0, false, ErrIllegalDirection
	}

	// Move the cursor back to the prefix (version and description).
	base = base[:dot]

	// Split the remaining string into the version and the description.
	// We expect the first underscore to be the separator.
	s0, s1, found := strings.Cut(base, "_")
	if !found {
		return 0, "", 0, false, ErrMissingSeparator
	}

	// Ensure neither the version nor the description segments are empty
	// strings.
	if s0 == "" {
		return 0, "", 0, false, ErrInvalidVersion
	}
	if s1 == "" {
		return 0, "", 0, false, ErrInvalidDescription
	}

	// Parse the version segment into a non-negative integer. The bit size of
	// 63 rejects values that would overflow the signed BIGINT column used by
	// database drivers to track applied versions.
	v, e := strconv.ParseUint(s0, 10, 63)
	if e != nil {
		return 0, "", 0, false, ErrInvalidVersion
	}

	// Finalize the version and sanitize the description by restoring spaces.
	version = int64(v)
	desc = strings.ReplaceAll(s1, "_", " ")

	return version, desc, direction, tx, nil
}

// List reads the underlying file system and returns all valid migrations.
//
// It parses all files matching the configured extension. Files that do not
// match the naming convention are skipped and logged at the debug level.
func (s *Source) List() ([]migrate.SourceScript, error) {
	var scripts []migrate.SourceScript

	fn := func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		name := d.Name()
		version, desc, direction, tx, skipped := s.Parse(name)
		if skipped != nil {
			s.logger.Debug(context.Background(),
				"Skipping file in migration directory",
				log.String("name", name),
				log.String("reason", skipped.Error()),
			)
			return nil // Ignore files that don't match the naming convention
		}

		content, err := fs.ReadFile(s.dir, path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %q: %w", path, err)
		}

		scripts = append(scripts, migrate.SourceScript{
			Version:     version,
			Description: desc,
			Direction:   direction,
			Path:        path,
			Content:     content,
			Tx:          tx,
		})

		return nil
	}

	err := fs.WalkDir(s.dir, ".", fn)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to traverse migration directory: %w",
			err,
		)
	}

	return scripts, nil
}

var _ migrate.Source = (*Source)(nil)
