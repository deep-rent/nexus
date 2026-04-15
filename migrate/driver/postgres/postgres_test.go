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
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/driver/postgres"
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

	db, err := sql.Open("postgres", ds)
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

func TestNew(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db,
		postgres.WithSchema("test_schema"),
		postgres.WithTable("test_table"),
	)
	if drv == nil {
		t.Fatal("postgres.New() = nil; want non-nil")
	}
	if drv.Parser() == nil {
		t.Fatal("d.Parser() = nil; want non-nil")
	}
}

func TestDriver_Init(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db)
	ctx := context.Background()

	// 1. Initial creation
	if err := drv.Init(ctx); err != nil {
		t.Errorf("Init() #1 err = %v; want nil", err)
	}

	// 2. Idempotency check
	if err := drv.Init(ctx); err != nil {
		t.Errorf("Init() #2 err = %v; want nil", err)
	}
}

func TestDriver_Locking(t *testing.T) {
	db := setupDB(t)

	d1 := postgres.New(db, postgres.WithLockID(12345))
	d2 := postgres.New(db,
		postgres.WithLockID(12345),
		postgres.WithLockTimeout(100*time.Millisecond),
	)

	ctx := context.Background()

	// Acquire lock with instance 1
	if err := d1.Lock(ctx); err != nil {
		t.Fatalf("d1.Lock() err = %v; want nil", err)
	}

	// Attempt to acquire same lock with instance 2 (should fail via timeout)
	if err := d2.Lock(ctx); err == nil {
		t.Error("d2.Lock() = nil; want timeout error")
	}

	// Release lock from instance 1
	if err := d1.Unlock(ctx); err != nil {
		t.Errorf("d1.Unlock() err = %v; want nil", err)
	}

	// Instance 2 should now succeed
	if err := d2.Lock(ctx); err != nil {
		t.Errorf("d2.Lock() err = %v; want nil", err)
	}

	if err := d2.Unlock(ctx); err != nil {
		t.Errorf("d2.Unlock() err = %v; want nil", err)
	}
}

func TestDriver_ExecuteAndApplied(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db)
	ctx := context.Background()

	if err := drv.Init(ctx); err != nil {
		t.Fatalf("Init() err = %v; want nil", err)
	}

	checksum := sha256.Sum256([]byte("1"))

	// 1. Execute UP migration
	err := drv.Execute(ctx, migrate.ParsedScript{
		Version:   1,
		Direction: migrate.Up,
		Checksum:  checksum,
		Statements: []string{
			"CREATE TABLE users (id INT PRIMARY KEY);",
			"INSERT INTO users (id) VALUES (1);",
		},
		Tx: true,
	})
	if err != nil {
		t.Fatalf("Execute(Up) err = %v; want nil", err)
	}

	applied, err := drv.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if got, want := len(applied), 1; got != want {
		t.Fatalf("len(applied) = %d; want %d", got, want)
	}
	if applied[0].Version != 1 {
		t.Errorf("applied[0].Version = %d; want 1", applied[0].Version)
	}
	if applied[0].Checksum != checksum {
		t.Errorf("applied[0].Checksum mismatch")
	}
	if applied[0].Dirty {
		t.Error("applied[0].Dirty = true; want false")
	}

	// 2. Execute DOWN migration
	err = drv.Execute(ctx, migrate.ParsedScript{
		Version:   1,
		Direction: migrate.Down,
		Statements: []string{
			"DROP TABLE users;",
		},
		Tx: true,
	})
	if err != nil {
		t.Fatalf("Execute(Down) err = %v; want nil", err)
	}

	applied, err = drv.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if len(applied) != 0 {
		t.Errorf("len(applied) = %d; want 0", len(applied))
	}
}

func TestDriver_Execute_FailureRollback(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db)
	ctx := context.Background()

	if err := drv.Init(ctx); err != nil {
		t.Fatalf("Init() err = %v; want nil", err)
	}

	script := migrate.ParsedScript{
		Version:   2,
		Direction: migrate.Up,
		Checksum:  sha256.Sum256([]byte("fail")),
		Statements: []string{
			"CREATE TABLE posts (id INT PRIMARY KEY);",
			"SYNTAX ERROR TRIGGER ROLLBACK;",
		},
		Tx: true,
	}

	if err := drv.Execute(ctx, script); err == nil {
		t.Error("Execute() = nil; want syntax error")
	}

	// Verify the database state is marked as dirty
	applied, err := drv.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if got, want := len(applied), 1; got != want {
		t.Fatalf("len(applied) = %d; want %d", got, want)
	}
	if !applied[0].Dirty {
		t.Error("applied[0].Dirty = false; want true")
	}

	// Verify the table creation was rolled back
	var count int
	query := `
    SELECT count(*) FROM information_schema.tables WHERE table_name = 'posts'
  `
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		t.Fatalf("query err = %v; want nil", err)
	}
	if count != 0 {
		t.Errorf("count = %d; want 0 (rolled back)", count)
	}
}

func TestDriver_Force(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db)
	ctx := context.Background()

	if err := drv.Init(ctx); err != nil {
		t.Fatalf("Init() err = %v; want nil", err)
	}

	// Manually inject a dirty state at version 1 and a clean state at version 2
	query := `
    INSERT INTO migrations (version, checksum, dirty)
    VALUES (1, '\x01', true), (2, '\x02', false)
  `
	if _, err := db.ExecContext(ctx, query); err != nil {
		t.Fatalf("manual insert err = %v; want nil", err)
	}

	// Force back to version 1
	if err := drv.Force(ctx, 1); err != nil {
		t.Errorf("Force(1) err = %v; want nil", err)
	}

	applied, err := drv.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if got, want := len(applied), 1; got != want {
		t.Fatalf("len(applied) = %d; want %d", got, want)
	}
	if applied[0].Version != 1 {
		t.Errorf("applied[0].Version = %d; want 1", applied[0].Version)
	}
	if applied[0].Dirty {
		t.Error("applied[0].Dirty = true; want false")
	}
}

func TestDriver_Execute_NonTransactional(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db)
	ctx := context.Background()

	if err := drv.Init(ctx); err != nil {
		t.Fatalf("Init() err = %v; want nil", err)
	}

	err := drv.Execute(ctx, migrate.ParsedScript{
		Version:   1,
		Direction: migrate.Up,
		Checksum:  sha256.Sum256([]byte("notx")),
		Statements: []string{
			"CREATE TABLE metrics (id INT);",
			"CREATE INDEX CONCURRENTLY idx_metrics_id ON metrics(id);",
		},
		Tx: false,
	})
	if err != nil {
		t.Errorf("Execute(Tx: false) err = %v; want nil", err)
	}

	applied, err := drv.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if len(applied) != 1 {
		t.Errorf("len(applied) = %d; want 1", len(applied))
	}
}

func TestDriver_Execute_StatementTimeout(t *testing.T) {
	db := setupDB(t)

	// Set an aggressive timeout
	drv := postgres.New(db, postgres.WithStatementTimeout(50*time.Millisecond))
	ctx := context.Background()

	if err := drv.Init(ctx); err != nil {
		t.Fatalf("Init() err = %v; want nil", err)
	}

	err := drv.Execute(ctx, migrate.ParsedScript{
		Version:   1,
		Direction: migrate.Up,
		Statements: []string{
			"SELECT pg_sleep(1);",
		},
		Tx: true,
	})

	if err == nil {
		t.Error("Execute() = nil; want statement timeout error")
	}
}

func TestDriver_Close(t *testing.T) {
	db := setupDB(t)

	drv := postgres.New(db)
	ctx := context.Background()

	if err := drv.Close(); err != nil {
		t.Errorf("Close() err = %v; want nil", err)
	}

	// Verify the underlying pool is closed
	if err := db.PingContext(ctx); err == nil {
		t.Error("Ping() = nil; want database closed error")
	}
}
