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
// Example Usage:
//
//	// Using an embedded filesystem
//	//go:embed sql/*.sql
//	var fs embed.FS
//
//	src := file.New(fs, file.WithExtension(".sql"), file.WithLogger(logger))
//	migrations, err := src.List()
package file

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"

	"github.com/deep-rent/nexus/migrate"
)

const (
	// DefaultExtension is the default file extension used when searching for
	// migration scripts in the file system.
	DefaultExtension = ".sql"
)

// Errors explaining why the Parse method has failed:
var (
	// ErrExtension is returned when a filename does not end with the configured
	// file extension.
	ErrExtension = errors.New("extension mismatch")
	// ErrMissingDirection is returned when a filename lacks the dot separator
	// preceding the direction segment.
	ErrMissingDirection = errors.New("missing direction segment")
	// ErrIllegalDirection is returned when the direction segment is neither "up"
	// nor "down".
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

// config holds the internal configuration options for the file source.
type config struct {
	ext    string
	logger *slog.Logger
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

// WithLogger injects a structured logger to record file parsing skipped files.
// Nil values are ignored, falling back to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Source implements the migrate.Source interface for an fs.FS.
// It scans the file system to discover and parse migration files.
type Source struct {
	dir    fs.FS        // File system containing the migration scripts
	ext    string       // File extension used to filter relevant scripts
	logger *slog.Logger // Logger used for debugging missed conventions
}

// New creates a new Source instance that reads from the provided fs.FS.
// Options can be provided to customize behavior, such as changing the
// expected file extension.
func New(dir fs.FS, opts ...Option) *Source {
	cfg := &config{
		ext:    DefaultExtension,
		logger: slog.Default(),
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

// Parse extracts the version, description, execution direction, and transaction
// flag from a given filename. It returns an error if the filename does not
// match the strict <version>_<description>.<direction>[_notx]<extension>
// format.
func (s *Source) Parse(name string) (
	version uint64,
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
		return 0, "", -1, false, ErrExtension
	}

	// Locate the dot that separates the version/description from the direction.
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return 0, "", -1, false, ErrMissingDirection
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

	// Ensure neither the version nor the description segments are empty strings.
	if s0 == "" {
		return 0, "", 0, false, ErrInvalidVersion
	}
	if s1 == "" {
		return 0, "", 0, false, ErrInvalidDescription
	}

	// Parse the version segment into an unsigned long.
	v, e := strconv.ParseUint(s0, 10, 64)
	if e != nil {
		return 0, "", 0, false, ErrInvalidVersion
	}

	// Finalize the version and sanitize the description by restoring spaces.
	version = v
	desc = strings.ReplaceAll(s1, "_", " ")

	return version, desc, direction, tx, nil
}

// List reads the underlying file system, parses all files matching the
// configured extension, and returns a complete list of valid migrations.
func (s *Source) List() ([]migrate.SourceScript, error) {
	var scripts []migrate.SourceScript

	fn := func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		name := d.Name()
		version, desc, direction, tx, skipped := s.Parse(name)
		if skipped != nil {
			s.logger.Debug(
				"Skipping file in migration directory",
				slog.String("name", name),
				slog.String("reason", skipped.Error()),
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
		return nil, fmt.Errorf("failed to traverse migration directory: %w", err)
	}

	return scripts, nil
}

// Ensure Source satisfies the migrate.Source interface.
var _ migrate.Source = (*Source)(nil)
