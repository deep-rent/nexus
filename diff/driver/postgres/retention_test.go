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
	"time"

	"uuid"

	"github.com/deep-rent/nexus/diff/driver/postgres"
	"github.com/deep-rent/nexus/schedule"
)

// Retention must remain schedulable as-is; this pins the implicit contract
// with the schedule package.
var _ schedule.Task = (*postgres.Retention)(nil)

func TestNewRetention_PanicsOnNilStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("should have panicked")
		}
	}()
	postgres.NewRetention(nil)
}

// count returns the number of rows in the given bookkeeping table.
func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count: should not have returned an error: %v", err)
	}
	return n
}

func TestRetention_Run(t *testing.T) {
	db, s := setupStore(t)
	user := newUser(t, db)

	// Seed two mutation records and one tombstone.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		_, err := s.Claim(ctx, tx, user,
			[]uuid.UUID{uuid.NewV7(), uuid.NewV7()})
		return err
	})
	if _, err := db.Exec(
		"INSERT INTO document_tombstones"+
			" (type, id, user_id, team_id, hlc, seq, deleted_at)"+
			" VALUES ('asset', $1, $2, NULL, 10,"+
			" nextval('document_seq'), now())",
		uuid.NewV7(), user,
	); err != nil {
		t.Fatalf("seed tombstone: should not have returned an error: %v", err)
	}

	// A pass with the default windows prunes nothing.
	postgres.NewRetention(s).Run(context.Background())
	if got := count(t, db, "document_mutations"); got != 2 {
		t.Errorf("mutations after default pass: got %d; want 2", got)
	}
	if got := count(t, db, "document_tombstones"); got != 1 {
		t.Errorf("tombstones after default pass: got %d; want 1", got)
	}

	// A pass with tiny windows prunes both tables and advances the floor.
	time.Sleep(20 * time.Millisecond)
	postgres.NewRetention(s,
		postgres.WithMutationRetention(10*time.Millisecond),
		postgres.WithTombstoneRetention(10*time.Millisecond),
	).Run(context.Background())
	if got := count(t, db, "document_mutations"); got != 0 {
		t.Errorf("mutations after tiny pass: got %d; want 0", got)
	}
	if got := count(t, db, "document_tombstones"); got != 0 {
		t.Errorf("tombstones after tiny pass: got %d; want 0", got)
	}
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		floor, err := s.Floor(ctx, tx)
		if err != nil {
			return err
		}
		if floor == 0 {
			t.Error("floor: got 0; want advanced past the pruned tombstone")
		}
		return nil
	})
}
