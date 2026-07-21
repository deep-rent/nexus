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

// Package schema provides utilities for parsing and manipulating database
// schema definitions and migration scripts.
//
// Its primary responsibility is to safely split raw SQL scripts into individual
// statements so they can be executed sequentially by a database driver. The
// parsing logic is designed to be aware of database-specific syntax, such as
// string literals, comments, and dollar-quoted strings in PostgreSQL, to
// prevent false positives when splitting on statement terminators like
// semicolons.
//
// # Usage
//
// Use the provided [Parser] implementations to break down SQL migration files
// into executable chunks.
//
// Example:
//
//	script := []byte(
//	  "CREATE TABLE users (id int); -- comment\nINSERT INTO users VALUES (1);",
//	)
//	statements := schema.Postgres(script)
//	// returns ["CREATE TABLE users (id int)", "INSERT INTO users VALUES (1)"]
package schema
