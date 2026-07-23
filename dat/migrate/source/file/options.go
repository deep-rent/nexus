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
	"log/slog"
	"strings"
)

const (
	// DefaultExtension is the default file extension used when searching for
	// migration scripts in the file system.
	DefaultExtension = ".sql"
)

// config holds the internal configuration options for the file source.
type config struct {
	// ext is the file extension to filter for.
	ext string
	// logger is the structured logger for reporting skipped files.
	logger *slog.Logger
}

// Option configures a [Source] instance.
type Option func(*config)

// WithExtension sets a custom file extension for migration files.
//
// It automatically prepends a leading dot if one is missing. Empty string
// values are ignored.
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

// WithLogger injects a structured logger to record skipped files.
//
// Nil values are ignored, falling back to [slog.Default].
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}
