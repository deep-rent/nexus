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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/driver/postgres"
)

func setup(t *testing.T) *sql.DB {
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
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	ds, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", ds)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, db.Close())
	})

	return db
}

func TestNew(t *testing.T) {
	db := setup(t)
	d := postgres.New(db,
		postgres.WithSchema("test_schema"),
		postgres.WithTable("test_table"),
	)
	require.NotNil(t, d)
	require.NotNil(t, d.Parser())
}

func TestDriver_Init(t *testing.T) {
	db := setup(t)
	d := postgres.New(db)
	ctx := context.Background()

	// 1. Initial creation
	err := d.Init(ctx)
	assert.NoError(t, err)

	// 2. Idempotency check (should not fail if table already exists)
	err = d.Init(ctx)
	assert.NoError(t, err)
}

func TestDriver_Locking(t *testing.T) {
	db := setup(t)
	ctx := context.Background()

	d1 := postgres.New(db,
		postgres.WithLockID(12345),
	)
	d2 := postgres.New(db,
		postgres.WithLockID(12345),
		postgres.WithLockTimeout(100*time.Millisecond),
	)

	// Acquire lock with instance 1
	err := d1.Lock(ctx)
	assert.NoError(t, err)

	// Attempt to acquire same lock with instance 2 (should fail via timeout)
	err = d2.Lock(ctx)
	assert.ErrorContains(t, err, "failed to acquire advisory lock")

	// Release lock from instance 1
	err = d1.Unlock(ctx)
	assert.NoError(t, err)

	// Instance 2 should now succeed
	err = d2.Lock(ctx)
	assert.NoError(t, err)
	assert.NoError(t, d2.Unlock(ctx))
}

func TestDriver_ExecuteAndApplied(t *testing.T) {
	db := setup(t)
	d := postgres.New(db)
	ctx := context.Background()
	require.NoError(t, d.Init(ctx))

	checksum := sha256.Sum256([]byte("1"))

	// 1. Execute UP migration
	err := d.Execute(ctx, migrate.ParsedScript{
		Version:   1,
		Direction: migrate.Up,
		Checksum:  checksum,
		Statements: []string{
			"CREATE TABLE users (id INT PRIMARY KEY);",
			"INSERT INTO users (id) VALUES (1);",
		},
		Tx: true,
	})
	require.NoError(t, err)

	applied, err := d.Applied(ctx)
	require.NoError(t, err)
	require.Len(t, applied, 1)
	assert.Equal(t, uint64(1), applied[0].Version)
	assert.Equal(t, checksum, applied[0].Checksum)
	assert.False(t, applied[0].Dirty)

	err = d.Execute(ctx, migrate.ParsedScript{
		Version:   1,
		Direction: migrate.Down,
		Statements: []string{
			"DROP TABLE users;",
		},
		Tx: true,
	})
	require.NoError(t, err)

	applied, err = d.Applied(ctx)
	require.NoError(t, err)
	assert.Empty(t, applied)
}

func TestDriver_ExecuteFailureRollback(t *testing.T) {
	db := setup(t)
	d := postgres.New(db)
	ctx := context.Background()
	require.NoError(t, d.Init(ctx))

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

	err := d.Execute(ctx, script)
	assert.ErrorContains(t, err, "statement 2 failed")

	// Verify the database state is marked as dirty
	applied, err := d.Applied(ctx)
	require.NoError(t, err)
	require.Len(t, applied, 1)
	assert.True(t, applied[0].Dirty)

	// Verify the table creation was rolled back
	var count int
	err = db.QueryRow(
		"SELECT count(*) FROM information_schema.tables WHERE table_name = 'posts'",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "table should not exist due to rollback")
}

func TestDriver_Force(t *testing.T) {
	db := setup(t)
	d := postgres.New(db)
	ctx := context.Background()
	require.NoError(t, d.Init(ctx))

	// Manually inject a dirty state at version 1 and a clean state at version 2
	_, err := db.Exec(`
		INSERT INTO migrations (version, checksum, dirty) VALUES
		(1, '\x01', true),
		(2, '\x02', false)
	`)
	require.NoError(t, err)

	// Force back to version 1
	err = d.Force(ctx, 1)
	assert.NoError(t, err)

	applied, err := d.Applied(ctx)
	require.NoError(t, err)
	require.Len(t, applied, 1)
	assert.Equal(t, uint64(1), applied[0].Version)
	assert.False(t, applied[0].Dirty, "dirty flag should be cleared")
}
