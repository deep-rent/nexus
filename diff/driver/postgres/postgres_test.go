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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"uuid"

	"github.com/deep-rent/nexus/diff/driver/postgres"
	"github.com/deep-rent/nexus/internal/schema"
)

func setupDB(t *testing.T) *sql.DB {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test: database setup required")
	}

	ctx := context.Background()

	container, err := testpg.Run(ctx,
		"postgres:18-alpine",
		testpg.WithDatabase("testdb"),
		testpg.WithUsername("user"),
		testpg.WithPassword("pass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(10*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Errorf("failed to terminate container: %v", err)
		}
	})

	ds, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", ds)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("failed to close database: %v", err)
		}
	})

	return db
}

func setupStore(t *testing.T) (*sql.DB, *postgres.Store) {
	t.Helper()

	db := setupDB(t)
	provisionSchema(t, db)
	return db, postgres.New(db)
}

// provisionSchema creates the application-owned schema: minimal users and
// teams tables plus the store's bookkeeping objects from the reference
// migration file. The schema is owned by the application, so the tests act
// as one.
func provisionSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// The reference migration declares foreign keys against the
	// application-owned users and teams tables; create minimal stand-ins
	// first.
	for _, stmt := range []string{
		"CREATE TABLE users (id UUID PRIMARY KEY)",
		"CREATE TABLE teams (id UUID PRIMARY KEY)",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create table: should not have returned an error: %v", err)
		}
	}

	execScript(t, db, "1_document.up.sql")
}

// execScript reads the named reference migration file from disk and executes
// its statements in order.
func execScript(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	script, err := os.ReadFile(filepath.Join("migrations", name))
	if err != nil {
		t.Fatalf("read script: should not have returned an error: %v", err)
	}
	for _, stmt := range schema.Postgres(script) {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			t.Fatalf("exec script: should not have returned an error: %v", err)
		}
	}
}

// newUser registers a fresh user and returns its id, satisfying the foreign
// keys of the bookkeeping and document tables.
func newUser(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	if _, err := db.Exec(
		"INSERT INTO users (id) VALUES ($1)", id,
	); err != nil {
		t.Fatalf("insert user: should not have returned an error: %v", err)
	}
	return id
}

// newTeam registers a fresh team and returns its id, satisfying the foreign
// keys of the bookkeeping and document tables.
func newTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.NewV7()
	if _, err := db.Exec(
		"INSERT INTO teams (id) VALUES ($1)", id,
	); err != nil {
		t.Fatalf("insert team: should not have returned an error: %v", err)
	}
	return id
}

// inTx runs fn inside a committed store transaction, failing the test on
// error.
func inTx(
	t *testing.T,
	s *postgres.Store,
	fn func(ctx context.Context, tx *sql.Tx) error,
) {
	t.Helper()
	if err := s.Exec(context.Background(), fn); err != nil {
		t.Fatalf("exec: should not have returned an error: %v", err)
	}
}

func TestNew_PanicsOnNilDB(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("new with nil db: should have panicked")
		}
	}()
	postgres.New(nil)
}

func TestMigrations_Reference(t *testing.T) {
	db := setupDB(t)
	s := postgres.New(db)

	// The reference up migration must apply cleanly against the
	// application-owned users and teams tables, and stay idempotent.
	provisionSchema(t, db)
	execScript(t, db, "1_document.up.sql")

	// The store must be functional on the provisioned schema.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		floor, err := s.Floor(ctx, tx)
		if err != nil {
			return err
		}
		if floor != 0 {
			t.Errorf("got floor %d; want 0", floor)
		}
		return nil
	})

	// The reference down migration must revert cleanly, and the schema must
	// re-apply afterwards.
	execScript(t, db, "1_document.down.sql")
	execScript(t, db, "1_document.up.sql")
}

func TestStore_ExecRollback(t *testing.T) {
	db, s := setupStore(t)

	user := newUser(t, db)
	id := uuid.NewV7()
	boom := errors.New("boom")

	err := s.Exec(context.Background(),
		func(ctx context.Context, tx *sql.Tx) error {
			if _, err := s.Claim(ctx, tx, user, []uuid.UUID{id}); err != nil {
				return err
			}
			return boom
		})
	if !errors.Is(err, boom) {
		t.Fatalf("got error %v; want %v", err, boom)
	}

	// The failed transaction must have rolled back its claim.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		claimed, err := s.Claim(ctx, tx, user, []uuid.UUID{id})
		if err != nil {
			return err
		}
		if len(claimed) != 1 {
			t.Errorf("got %d claimed; want 1 (rolled back)", len(claimed))
		}
		return nil
	})
}

func TestStore_Claim(t *testing.T) {
	db, s := setupStore(t)

	user := newUser(t, db)
	a, b, c := uuid.NewV7(), uuid.NewV7(), uuid.NewV7()

	// Duplicates within one call claim once.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		claimed, err := s.Claim(ctx, tx, user, []uuid.UUID{a, b, a})
		if err != nil {
			return err
		}
		if got, want := len(claimed), 2; got != want {
			t.Errorf("got %d claimed; want %d", got, want)
		}
		if !slices.Contains(claimed, a) || !slices.Contains(claimed, b) {
			t.Errorf("got claimed %v; want both %v and %v", claimed, a, b)
		}
		return nil
	})

	// Previously claimed ids are filtered out.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		claimed, err := s.Claim(ctx, tx, user, []uuid.UUID{a, c})
		if err != nil {
			return err
		}
		if got, want := len(claimed), 1; got != want {
			t.Fatalf("got %d claimed; want %d", got, want)
		}
		if claimed[0] != c {
			t.Errorf("got claimed %v; want %v", claimed[0], c)
		}
		return nil
	})

	// Empty input is a no-op.
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		claimed, err := s.Claim(ctx, tx, user, nil)
		if err != nil {
			return err
		}
		if len(claimed) != 0 {
			t.Errorf("got %d claimed; want 0", len(claimed))
		}
		return nil
	})
}

func TestStore_Claim_Concurrent(t *testing.T) {
	db, s := setupStore(t)

	user := newUser(t, db)
	ids := make([]uuid.UUID, 5)
	for i := range ids {
		ids[i] = uuid.NewV7()
	}

	type result struct {
		claimed []uuid.UUID
		err     error
	}
	results := make(chan result, 2)

	for range 2 {
		go func() {
			var claimed []uuid.UUID
			err := s.Exec(context.Background(),
				func(ctx context.Context, tx *sql.Tx) error {
					var err error
					claimed, err = s.Claim(ctx, tx, user, ids)
					if err != nil {
						return err
					}
					// Hold the transaction open so the competing claim
					// blocks on the conflicting inserts.
					time.Sleep(50 * time.Millisecond)
					return nil
				})
			results <- result{claimed: claimed, err: err}
		}()
	}

	counts := make(map[uuid.UUID]int)
	for range 2 {
		res := <-results
		if res.err != nil {
			t.Fatalf("claim: should not have returned an error: %v", res.err)
		}
		for _, id := range res.claimed {
			counts[id]++
		}
	}

	for _, id := range ids {
		if got := counts[id]; got != 1 {
			t.Errorf("id %v: got %d claims; want exactly 1", id, got)
		}
	}
}

func TestStore_Sequence(t *testing.T) {
	_, s := setupStore(t)

	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		floor, err := s.Floor(ctx, tx)
		if err != nil {
			return err
		}
		if floor != 0 {
			t.Errorf("got floor %d; want 0", floor)
		}

		mark, err := s.Watermark(ctx, tx)
		if err != nil {
			return err
		}
		if mark != 0 {
			t.Errorf("got fresh watermark %d; want 0", mark)
		}

		b1, err := s.Barrier(ctx, tx)
		if err != nil {
			return err
		}
		if b1 != 1 {
			t.Errorf("got first barrier %d; want 1", b1)
		}

		mark, err = s.Watermark(ctx, tx)
		if err != nil {
			return err
		}
		if mark != b1 {
			t.Errorf("got watermark %d; want %d", mark, b1)
		}

		b2, err := s.Barrier(ctx, tx)
		if err != nil {
			return err
		}
		if b2 != b1+1 {
			t.Errorf("got second barrier %d; want %d", b2, b1+1)
		}
		return nil
	})
}

func TestStore_Lock_Concurrent(t *testing.T) {
	_, s := setupStore(t)

	keys := make([]uuid.UUID, 5)
	for i := range keys {
		keys[i] = uuid.NewV7()
	}
	reversed := slices.Clone(keys)
	slices.Reverse(reversed)

	// Overlapping exclusive lock sets acquired in opposite order must
	// serialize without deadlocking, because Lock sorts the derived keys
	// internally.
	errs := make(chan error, 2)
	for _, set := range [][]uuid.UUID{keys, reversed} {
		go func(set []uuid.UUID) {
			errs <- s.Exec(context.Background(),
				func(ctx context.Context, tx *sql.Tx) error {
					if err := s.Lock(ctx, tx, nil, set); err != nil {
						return err
					}
					time.Sleep(50 * time.Millisecond)
					return nil
				})
		}(set)
	}

	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("lock: should not have returned an error: %v", err)
		}
	}
}

func TestStore_Lock_SharedExclusive(t *testing.T) {
	_, s := setupStore(t)

	ctx := context.Background()
	key := uuid.NewV7()

	// hold acquires the given locks in a background transaction, signals
	// once they are held, and keeps the transaction open until released.
	hold := func(
		shared, exclusive []uuid.UUID,
	) (held, release chan struct{}, done chan error) {
		held = make(chan struct{})
		release = make(chan struct{})
		done = make(chan error, 1)
		go func() {
			done <- s.Exec(ctx, func(ctx context.Context, tx *sql.Tx) error {
				if err := s.Lock(ctx, tx, shared, exclusive); err != nil {
					return err
				}
				close(held)
				<-release
				return nil
			})
		}()
		return held, release, done
	}

	// acquire attempts the given locks in a background transaction and
	// reports completion.
	acquire := func(shared, exclusive []uuid.UUID) chan error {
		ch := make(chan error, 1)
		go func() {
			ch <- s.Exec(ctx, func(ctx context.Context, tx *sql.Tx) error {
				return s.Lock(ctx, tx, shared, exclusive)
			})
		}()
		return ch
	}

	// Two shared lockers on a common key proceed concurrently.
	held, release, done := hold([]uuid.UUID{key}, nil)
	<-held
	select {
	case err := <-acquire([]uuid.UUID{key}, nil):
		if err != nil {
			t.Fatalf("shared lock: should not have returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shared lock: should not have blocked on a shared holder")
	}

	// An exclusive locker blocks on the shared holder and proceeds once the
	// reader releases.
	writer := acquire(nil, []uuid.UUID{key})
	select {
	case err := <-writer:
		t.Fatalf("exclusive lock: should have blocked on a shared holder"+
			" (got error %v)", err)
	case <-time.After(150 * time.Millisecond):
		// Blocked, as expected.
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("holder: should not have returned an error: %v", err)
	}
	select {
	case err := <-writer:
		if err != nil {
			t.Fatalf(
				"exclusive lock: should not have returned an error: %v",
				err,
			)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive lock: should have completed after release")
	}

	// A key listed in both sets is locked exclusively: a shared locker
	// blocks on it.
	held, release, done = hold([]uuid.UUID{key}, []uuid.UUID{key})
	<-held
	reader := acquire([]uuid.UUID{key}, nil)
	select {
	case err := <-reader:
		t.Fatalf("shared lock: should have blocked on a mixed-mode holder"+
			" (got error %v)", err)
	case <-time.After(150 * time.Millisecond):
		// Blocked, as expected.
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("holder: should not have returned an error: %v", err)
	}
	select {
	case err := <-reader:
		if err != nil {
			t.Fatalf("shared lock: should not have returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shared lock: should have completed after release")
	}
}

func TestStore_Grants(t *testing.T) {
	db, s := setupStore(t)

	owner1 := newUser(t, db)
	owner2 := newUser(t, db)
	other := newUser(t, db)
	teamA := newTeam(t, db)
	teamB := newTeam(t, db)

	seed := []struct {
		user uuid.UUID
		team uuid.UUID
	}{
		{owner1, teamA},
		{owner1, teamB},
		{owner2, teamA},
	}
	for i, g := range seed {
		if _, err := db.Exec(
			"INSERT INTO document_shares (id, user_id, team_id, hlc, seq)"+
				" VALUES ($1, $2, $3, $4, $5)",
			uuid.NewV7(), g.user, g.team, 10+i, i+1,
		); err != nil {
			t.Fatalf("insert share: should not have returned an error: %v", err)
		}
	}

	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		grants, err := s.Grants(ctx, tx, []uuid.UUID{owner1, owner2, other})
		if err != nil {
			return err
		}
		if got, want := len(grants), 2; got != want {
			t.Errorf("got %d granted owners; want %d", got, want)
		}
		teams := grants[owner1]
		slices.SortFunc(teams, uuid.UUID.Compare)
		want := []uuid.UUID{teamA, teamB}
		slices.SortFunc(want, uuid.UUID.Compare)
		if !slices.Equal(teams, want) {
			t.Errorf("got teams %v for owner1; want %v", teams, want)
		}
		if got := grants[owner2]; !slices.Equal(got, []uuid.UUID{teamA}) {
			t.Errorf("got teams %v for owner2; want [%v]", got, teamA)
		}
		if got, exists := grants[other]; exists {
			t.Errorf("got teams %v for ungranted owner; want absence", got)
		}

		// Empty input yields an empty map.
		grants, err = s.Grants(ctx, tx, nil)
		if err != nil {
			return err
		}
		if len(grants) != 0 {
			t.Errorf("got %d granted owners; want 0", len(grants))
		}
		return nil
	})
}

func TestStore_Mutate(t *testing.T) {
	_, s := setupStore(t)

	scope := scopeOf(uuid.NewV7(), uuid.NewV7())

	called := false
	err := s.Mutate(context.Background(), scope,
		func(ctx context.Context, tx *sql.Tx) error {
			called = true
			_, err := s.Barrier(ctx, tx)
			return err
		})
	if err != nil {
		t.Errorf("mutate: should not have returned an error: %v", err)
	}
	if !called {
		t.Error("mutate: should have invoked fn")
	}

	boom := errors.New("boom")
	err = s.Mutate(context.Background(), scope,
		func(ctx context.Context, tx *sql.Tx) error {
			return boom
		})
	if !errors.Is(err, boom) {
		t.Errorf("got error %v; want %v", err, boom)
	}
}

func TestStore_PruneMutations(t *testing.T) {
	db, s := setupStore(t)

	user := newUser(t, db)
	ids := []uuid.UUID{uuid.NewV7(), uuid.NewV7(), uuid.NewV7()}
	inTx(t, s, func(ctx context.Context, tx *sql.Tx) error {
		_, err := s.Claim(ctx, tx, user, ids)
		return err
	})

	// Young mutations survive.
	n, err := s.PruneMutations(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("prune: should not have returned an error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d pruned; want 0", n)
	}

	// Aged mutations are removed.
	time.Sleep(20 * time.Millisecond)
	n, err = s.PruneMutations(context.Background(), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("prune: should not have returned an error: %v", err)
	}
	if got, want := n, int64(len(ids)); got != want {
		t.Errorf("got %d pruned; want %d", got, want)
	}
}
