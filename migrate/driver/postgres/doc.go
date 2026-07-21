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

// Queries concatenate only the quoted identifier from quote.Ident; all
// values are passed as bind parameters:
//gosec:disable G202 -- identifiers are escaped, values are parameterized

// Package postgres provides a PostgreSQL-specific driver for the migrate
// package.
//
// It executes database migrations, manages the state of applied migrations,
// and ensures concurrent safety using PostgreSQL advisory locks. The driver
// supports configurable schema and table names for state tracking, structured
// logging, and transactional execution of migration scripts.
//
// # Usage
//
// Initialize the driver with an existing [*sql.DB] connection and optional
// configuration functions.
//
// Example:
//
//	db, _ := sql.Open("postgres", "postgres://user:pass@localhost:5432/db")
//	drv := postgres.New(db,
//	    postgres.WithSchema("public"),
//	    postgres.WithTable("migrations"),
//	)
package postgres
