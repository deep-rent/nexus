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

// Package quote provides utility functions for working with quoted strings.
//
// It offers a suite of tools for detecting, applying, and stripping single or
// double quotes from string data. These utilities are particularly helpful
// when parsing configuration files, processing CLI arguments, or normalizing
// user input where string literals may be wrapped in various quote styles.
//
// # Usage
//
// The package supports both single-layer operations and recursive unquoting.
//
// Example:
//
//	// Remove a single layer
//	s := quote.Remove(`"hello"`) // returns: hello
//
//	// Remove nested layers
//	s = quote.RemoveAll(`"'nested'"`) // returns: nested
//
//	// Wrap content
//	s = quote.Double("content") // returns: "content"
//
// It also provides SQL quoting helpers that escape embedded quotes:
//
//	// Quote SQL identifiers and literals
//	s = quote.Ident("public", "users") // returns: "public"."users"
//	s = quote.Literal("it's")          // returns: 'it''s'
package quote
