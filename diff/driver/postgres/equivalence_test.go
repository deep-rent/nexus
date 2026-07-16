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

package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/deep-rent/nexus/diff/driver/drivertest"
)

// TestEquivalence runs the shared driver equivalence suite against the
// postgres reference driver. It reuses one container across scenarios; each
// scenario seeds fresh users, teams, and document ids, so the shared schema
// stays isolated. The setup skips under -short.
func TestEquivalence(t *testing.T) {
	db, s, assets, files, _ := setupTables(t)
	shares := s.Shares()

	newTarget := func(t *testing.T) drivertest.Target[*sql.Tx] {
		return drivertest.Target[*sql.Tx]{
			Store:    s,
			Root:     assets,
			Child:    files,
			Shares:   shares,
			ChildRef: "asset_id",
			InTx: func(t *testing.T, fn func(ctx context.Context, tx *sql.Tx) error) {
				inTx(t, s, fn)
			},
			SeedUser: func(t *testing.T) string { return newUser(t, db) },
			SeedTeam: func(t *testing.T) string { return newTeam(t, db) },
			Caps:     drivertest.Caps{DepartureTombstones: true},
		}
	}

	drivertest.RunEquivalence(t, newTarget)
}
