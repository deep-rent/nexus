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
	dir    fs.FS  // File system containing the migration scripts
	ext    string // File extension used to filter relevant scripts
	logger *slog.Logger
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

// List reads the underlying file system, parses all files matching the
// configured extension, and returns a complete list of valid migrations.
func (s *Source) List() ([]migrate.SourceScript, error) {
	var scripts []migrate.SourceScript

	fn := func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		name := d.Name()
		version, desc, direction, tx, skipped := s.parse(name)
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
			return fmt.Errorf("failed to read migration file %s: %w", path, err)
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
		return nil, fmt.Errorf("failed to read migration directory: %w", err)
	}

	return scripts, nil
}

// Ensure Source satisfies the migrate.Source interface.
var _ migrate.Source = (*Source)(nil)

// Errors returned by the parse function.
var (
	errExtension          = errors.New("extension mismatch")
	errMissingDirection   = errors.New("missing direction segment")
	errIllegalDirection   = errors.New("illegal direction")
	errMissingSeparator   = errors.New("missing underscore separator")
	errInvalidDescription = errors.New("invalid description")
	errInvalidVersion     = errors.New("invalid version")
)

// parse returns an error explaining why a file does not match the strict
// format.
func (s *Source) parse(name string) (
	version uint64,
	desc string,
	direction migrate.Direction,
	tx bool,
	err error,
) {
	tx = true
	base, found := strings.CutSuffix(name, s.ext)
	if !found {
		return 0, "", -1, false, errExtension
	}

	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return 0, "", -1, false, errMissingDirection
	}

	s2 := base[dot+1:]

	if disabled, found := strings.CutSuffix(s2, "_notx"); found {
		tx = false
		s2 = disabled
	}

	switch s2 {
	case "up":
		direction = migrate.Up
	case "down":
		direction = migrate.Down
	default:
		return 0, "", 0, false, errIllegalDirection
	}

	base = base[:dot]

	s0, s1, found := strings.Cut(base, "_")
	if !found {
		return 0, "", 0, false, errMissingSeparator
	}

	if s0 == "" {
		return 0, "", 0, false, errInvalidVersion
	}

	if s1 == "" {
		return 0, "", 0, false, errInvalidDescription
	}

	v, e := strconv.ParseUint(s0, 10, 64)
	if e != nil {
		return 0, "", 0, false, errInvalidVersion
	}

	version = v
	desc = strings.ReplaceAll(s1, "_", " ")

	return version, desc, direction, tx, nil
}
