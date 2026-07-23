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

package gzip

import (
	"compress/gzip"

	"github.com/deep-rent/nexus/std/ascii"
)

// Mirror constants from the [compress/gzip] package for easy access without
// requiring an extra import.
const (
	// BestCompression provides the highest level of compression.
	BestCompression = gzip.BestCompression
	// BestSpeed provides the fastest compression time.
	BestSpeed = gzip.BestSpeed
	// DefaultCompression provides a balance between speed and ratio.
	DefaultCompression = gzip.DefaultCompression
	// NoCompression disables compression entirely.
	NoCompression = gzip.NoCompression
)

// defaultExcludeList lists common media types that are already compressed.
var defaultExcludeList = []string{
	// Media
	"image/*",
	"video/*",
	"audio/*",
	// Fonts
	"font/*",
	// Archives & Documents
	"application/zip",
	"application/gzip",
	"application/pdf",
	"application/wasm",
}

// config holds the middleware configuration.
type config struct {
	// level is the compression level.
	level int
	// exclude is the list of MIME types to skip.
	exclude []string
}

// Option is a function that configures the middleware.
type Option func(*config)

// WithCompressionLevel sets the compression level.
//
// It accepts values ranging from [BestSpeed] (1) to [BestCompression] (9). For
// other values, it will fall back to [DefaultCompression], a good balance
// between speed and compression ratio.
func WithCompressionLevel(level int) Option {
	return func(c *config) {
		if level >= NoCompression && level <= BestCompression {
			c.level = level
		}
	}
}

// WithExcludeMimeTypes adds MIME types to the exclusion list.
//
// This option is additive and can be called multiple times; it appends to the
// default exclusion list rather than replacing it. The matching logic supports
// two formats:
//
//   - Exact: Provide the full MIME type (e.g., "application/pdf").
//   - Prefix: End the MIME type with a wildcard "*" (e.g., "image/*")
//     to exclude all subtypes for that primary type.
func WithExcludeMimeTypes(types ...string) Option {
	return func(c *config) {
		for _, t := range types {
			c.exclude = append(c.exclude, ascii.ToLower(t))
		}
	}
}
