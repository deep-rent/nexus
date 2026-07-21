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

// Explicitly allow SQL string concatenation:
// #nosec G202

// Package postgres provides the PostgreSQL reference driver for the diff
// synchronization engine.
//
// The [Store] implements the shared transactional machinery of
// [diff.Store]: sequencing, advisory locking, mutation deduplication, and
// tombstone retention. Models are backed by declarative [Table] handlers
// created with [NewTable], and the reserved "share" model is served by the
// built-in [Store.Shares] handler.
//
// # Usage
//
// Initialize the store with an existing [*sql.DB] connection and register
// one table per model.
//
// Example:
//
//	store := postgres.New(db)
//
//	assets := postgres.NewTable(store, "asset", "assets")
//	files := postgres.NewTable(store, "file", "files",
//	    postgres.WithParent("assets", "asset_id"))
//
//	reg := diff.NewRegistry[*sql.Tx]()
//	reg.Register[Asset]("asset", assets, diff.Root())
//	reg.Register[File]("file", files, diff.Owner("asset", "asset_id"))
//	reg.RegisterShares(store.Shares())
//
//	engine := diff.New(store, reg)
//
// The bookkeeping objects (and the document tables) are owned by the
// application: provision them through your own schema migrations before
// serving. The SQL files under migrations/ document the expected shape of
// the bookkeeping objects and serve as reference material.
package postgres
