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
	"log/slog"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/dat/diff"
	"github.com/deep-rent/nexus/dat/diff/driver/postgres"
)

// TestStore_Options constructs a store with every name option set to its
// default value (so the reference schema still matches) plus a logger,
// then drives a full round trip to confirm the configured store is
// functional. This exercises the option setters end to end.
func TestStore_Options(t *testing.T) {
	db := setupDB(t)
	provisionSchema(t, db)

	s := postgres.New(db,
		postgres.WithSchema("public"),
		postgres.WithMutationsTable("document_mutations"),
		postgres.WithTombstonesTable("document_tombstones"),
		postgres.WithStateTable("document_state"),
		postgres.WithSharesTable("document_shares"),
		postgres.WithSequence("document_seq"),
		postgres.WithLogger(slog.New(slog.DiscardHandler)),
		postgres.WithLogger(nil), // nil is ignored, keeps the prior logger
	)

	user := newUser(t, db)
	id := uuid.NewV7()
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		claimed, err := s.Claim(ctx, tx, user, []uuid.UUID{id})
		if err != nil {
			return err
		}
		if len(claimed) != 1 {
			t.Errorf("got %d claimed; want 1", len(claimed))
		}
		return nil
	})
}

// TestTable_WithTableSchema builds a table with an explicit schema option
// and confirms it operates against a purpose-provisioned table.
func TestTable_WithTableSchema(t *testing.T) {
	db, s := setupStore(t)

	if _, err := db.Exec(`CREATE TABLE things (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users (id),
		team_id UUID REFERENCES teams (id),
		hlc BIGINT NOT NULL,
		seq BIGINT NOT NULL,
		data JSONB NOT NULL)`); err != nil {
		t.Fatalf("create table: should not have returned an error: %v", err)
	}

	// Declaring the public schema explicitly must not change behavior.
	things := postgres.NewTable(s, "thing", "things",
		postgres.WithTableSchema("public"))

	owner := newUser(t, db)
	scope := scopeOf(owner)
	id := uuid.NewV7()
	applyUpserts(t, s, things, scope,
		upsertOp(id, owner, uuid.Nil(), 10, assetDoc(id, 1)))

	got := fetchAll(t, s, things, scope)
	if len(got) != 1 || got[0].ID != id {
		t.Errorf("got %v; want a single version for %v", got, id)
	}
}

// TestShares_Resolve covers the reference shares handler's Resolve method,
// which the engine calls to fold stored share identities into the lock set.
func TestShares_Resolve(t *testing.T) {
	db, s, _, _, _ := setupTables(t)
	shares := s.Shares()

	owner := newUser(t, db)
	team := newTeam(t, db)
	scope := scopeOf(owner)

	grant := uuid.NewV7()
	applyUpserts(t, s, shares, scope,
		upsertOp(grant, owner, team, 20, "{}"))

	// The stored share resolves to its owner/team identity; an unknown id
	// is simply absent from the result.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		metas, err := shares.Resolve(ctx, tx,
			[]uuid.UUID{grant, uuid.NewV7()})
		if err != nil {
			return err
		}
		if len(metas) != 1 {
			t.Fatalf("got %d metas; want 1", len(metas))
		}
		m, ok := metas[grant]
		if !ok {
			t.Fatalf("grant %v missing from resolve result", grant)
		}
		if m.UserID != owner {
			t.Errorf("owner: got %q; want %q", m.UserID, owner)
		}
		if m.TeamID != team {
			t.Errorf("team: got %v; want %v", m.TeamID, team)
		}
		return nil
	})
}

// inside the engine's lock fence.

// TestStore_Mutate_GrantFence proves that Mutate folds the acting user's
// granted teams into its exclusive lock set, so a backend write to an
// owner's personal documents serializes against readers of the teams those
// documents are shared to. Without the grant in the lock set, the competing
// exclusive locker on the team key would not block.
func TestStore_Mutate_GrantFence(t *testing.T) {
	db, s, _, _, _ := setupTables(t)
	shares := s.Shares()

	owner := newUser(t, db)
	team := newTeam(t, db)

	// Owner grants the team access to their personal documents.
	applyUpserts(t, s, shares, scopeOf(owner),
		upsertOp(uuid.NewV7(), owner, team, 10, "{}"))

	// Mutate under the owner's scope holds its locks open. A competing
	// exclusive locker on the granted team key must block until Mutate
	// commits, which can only happen if Mutate holds the team key.
	held := make(chan struct{})
	release := make(chan struct{})
	mutateDone := make(chan error, 1)
	go func() {
		mutateDone <- s.Mutate(context.Background(), scopeOf(owner),
			func(ctx context.Context, tx *sql.Tx) error {
				close(held)
				<-release
				return nil
			})
	}()
	<-held

	blocked := make(chan error, 1)
	go func() {
		blocked <- s.Exec(context.Background(),
			func(ctx context.Context, tx *sql.Tx) error {
				return s.Lock(ctx, tx, nil, []uuid.UUID{team})
			})
	}()

	// The competing locker must not complete while Mutate holds the team.
	select {
	case <-blocked:
		close(release)
		<-mutateDone
		t.Fatal("exclusive lock on the granted team should have blocked")
	case <-time.After(150 * time.Millisecond):
		// Expected: still blocked.
	}

	close(release)
	if err := <-mutateDone; err != nil {
		t.Fatalf("mutate: should not have returned an error: %v", err)
	}
	if err := <-blocked; err != nil {
		t.Errorf("blocked locker: should not have returned an error: %v", err)
	}
}

// TestStore_OffboardTeam proves the offboarding flow: burying a team's
// grants delivers a share tombstone to the team's members and frees the
// shares table of references to the team, so the team row can then be
// deleted despite the ON DELETE RESTRICT constraint.
func TestStore_OffboardTeam(t *testing.T) {
	db, s, assets, _, _ := setupTables(t)
	shares := s.Shares()

	owner := newUser(t, db)
	member := newUser(t, db)
	team := newTeam(t, db)
	ownerScope := scopeOf(owner)
	memberScope := scopeOf(member, team)

	// Owner has a personal document and grants the team access to it.
	doc := uuid.NewV7()
	applyUpserts(t, s, assets, ownerScope,
		upsertOp(doc, owner, uuid.Nil(), 10, assetDoc(doc, 1)))
	grant := uuid.NewV7()
	applyUpserts(t, s, shares, ownerScope,
		upsertOp(grant, owner, team, 20, "{}"))

	// The team member can see the shared document.
	if got := fetchAll(t, s, assets, memberScope); len(got) != 1 {
		t.Fatalf("before offboarding: got %d visible; want 1", len(got))
	}

	// Deleting the team while the grant exists is refused by the FK.
	if _, err := db.Exec(
		"DELETE FROM teams WHERE id = $1::uuid", team,
	); err == nil {
		t.Fatal("deleting a granted team should be refused by the FK")
	}

	// Offboard: bury the team's grants.
	buried, err := s.OffboardTeam(context.Background(), team, 30)
	if err != nil {
		t.Fatalf("offboard: should not have returned an error: %v", err)
	}
	if buried != 1 {
		t.Errorf("buried: got %d; want 1", buried)
	}

	// The member receives the share tombstone on their next sync.
	feed := fetchAll(t, s, s.Shares(),
		diff.Scope{UserID: member, Teams: []uuid.UUID{team}})
	var tomb bool
	for _, v := range feed {
		if v.ID == grant && v.Deleted {
			tomb = true
		}
	}
	if !tomb {
		t.Error("member should have received the share tombstone")
	}

	// The owner's personal document is no longer visible to the team.
	if got := fetchAll(t, s, assets, memberScope); len(got) != 0 {
		t.Errorf("after offboarding: got %d visible; want 0", len(got))
	}

	// The shares table no longer references the team.
	var live int
	if err := db.QueryRow(
		"SELECT count(*) FROM document_shares WHERE team_id = $1::uuid", team,
	).Scan(&live); err != nil {
		t.Fatalf("count shares: should not have returned an error: %v", err)
	}
	if live != 0 {
		t.Errorf("got %d live grants for the team; want 0", live)
	}

	// The team row still cannot be deleted: the grant tombstone the members
	// are owed references it. Once those tombstones are pruned, the team
	// becomes deletable — the two-phase offboarding lifecycle.
	if _, err := db.Exec(
		"DELETE FROM teams WHERE id = $1::uuid", team,
	); err == nil {
		t.Fatal("team deletion should await tombstone retention")
	}
	if _, err := s.PruneTombstones(context.Background(), 0); err != nil {
		t.Fatalf("prune: should not have returned an error: %v", err)
	}
	if _, err := db.Exec(
		"DELETE FROM teams WHERE id = $1::uuid", team,
	); err != nil {
		t.Errorf("deleting the reaped team: unexpected error: %v", err)
	}
}
