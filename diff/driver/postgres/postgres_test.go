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
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/diff/driver/postgres"
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
	s := postgres.New(db)
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: should not have returned an error: %v", err)
	}
	return db, s
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

func TestStore_Init(t *testing.T) {
	db := setupDB(t)

	s := postgres.New(db)
	ctx := context.Background()

	// 1. Initial creation
	if err := s.Init(ctx); err != nil {
		t.Errorf("on first call: should not have returned an error: %v", err)
	}

	// 2. Idempotency check
	if err := s.Init(ctx); err != nil {
		t.Errorf("on second call: should not have returned an error: %v", err)
	}
}

func TestDDLConstants(t *testing.T) {
	db := setupDB(t)
	ctx := context.Background()

	// The exported DDL must bootstrap a working default configuration.
	blocks := []string{
		postgres.DDLSequence,
		postgres.DDLMutations,
		postgres.DDLTombstones,
		postgres.DDLState,
		postgres.DDLShares,
	}
	for _, block := range blocks {
		for stmt := range strings.SplitSeq(block, ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("ddl: should not have returned an error: %v", err)
			}
		}
	}

	// Init must remain a no-op on top of the constants.
	s := postgres.New(db)
	if err := s.Init(ctx); err != nil {
		t.Errorf("init after ddl: should not have returned an error: %v", err)
	}
}

func TestStore_ExecRollback(t *testing.T) {
	_, s := setupStore(t)

	user := uuid.NewV7()
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
	_, s := setupStore(t)

	user := uuid.NewV7()
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
	_, s := setupStore(t)

	user := uuid.NewV7()
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

	// Overlapping lock sets acquired in opposite order must serialize
	// without deadlocking, because Lock sorts the derived keys internally.
	errs := make(chan error, 2)
	for _, set := range [][]uuid.UUID{keys, reversed} {
		go func(set []uuid.UUID) {
			errs <- s.Exec(context.Background(),
				func(ctx context.Context, tx *sql.Tx) error {
					if err := s.Lock(ctx, tx, set); err != nil {
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
	_, s := setupStore(t)

	user := uuid.NewV7()
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
