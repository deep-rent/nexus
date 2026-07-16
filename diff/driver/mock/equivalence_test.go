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

package mock_test

import (
	"context"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/diff/driver/drivertest"
	"github.com/deep-rent/nexus/diff/driver/mock"
)

// mockTarget builds a fresh in-memory backend for one equivalence scenario.
// The mock advertises no departure tombstones: it models neither cascades nor
// move tombstones, so those scenarios are skipped.
func mockTarget(t *testing.T) drivertest.Target[*mock.Tx] {
	store := mock.New()
	return drivertest.Target[*mock.Tx]{
		Store:    store,
		Root:     mock.NewHandler(store),
		Child:    mock.NewHandler(store),
		Shares:   mock.NewShares(store),
		ChildRef: "asset_id",
		InTx: func(t *testing.T, fn func(ctx context.Context, tx *mock.Tx) error) {
			t.Helper()
			if err := store.Exec(t.Context(), fn); err != nil {
				t.Fatalf("exec: should not have returned an error: %v", err)
			}
		},
		SeedUser: func(*testing.T) string { return uuid.NewV7().String() },
		SeedTeam: func(*testing.T) string { return uuid.NewV7().String() },
		Caps:     drivertest.Caps{DepartureTombstones: false},
	}
}

func TestEquivalence(t *testing.T) {
	t.Parallel()
	drivertest.RunEquivalence(t, mockTarget)
}
