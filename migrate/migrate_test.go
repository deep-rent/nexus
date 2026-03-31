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

package migrate_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/migrate"
	drivermock "github.com/deep-rent/nexus/migrate/driver/mock"
	"github.com/deep-rent/nexus/migrate/driver/postgres"
	"github.com/deep-rent/nexus/migrate/source/file"
	sourcemock "github.com/deep-rent/nexus/migrate/source/mock"
)

func TestNewMigrator(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		m := migrate.New(
			migrate.WithSource(sourcemock.New()),
			migrate.WithDriver(drivermock.New()),
		)
		require.NotNil(t, m)
	})

	t.Run("panic missing source", func(t *testing.T) {
		assert.PanicsWithValue(t, "migrate: source is required", func() {
			migrate.New(migrate.WithDriver(drivermock.New()))
		})
	})

	t.Run("panic missing driver", func(t *testing.T) {
		assert.PanicsWithValue(t, "migrate: driver is required", func() {
			migrate.New(migrate.WithSource(sourcemock.New()))
		})
	})
}

func TestMigrator_Up(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		up1 := []byte("CREATE TABLE users;")
		up2 := []byte("CREATE TABLE posts;")

		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   up1,
			},
			migrate.SourceScript{
				Version:   2,
				Direction: migrate.Up,
				Content:   up2,
			},
		)
		drv := drivermock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		assert.NoError(t, err)

		state := drv.State()
		assert.Len(t, state, 2)
		assert.Equal(t, sha256.Sum256(up1), state[1].Checksum)
		assert.Equal(t, sha256.Sum256(up2), state[2].Checksum)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("success up to date", func(t *testing.T) {
		up := []byte("CREATE TABLE users;")
		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   up,
			},
		)
		drv := drivermock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(up)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		assert.NoError(t, err)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("error locked", func(t *testing.T) {
		drv := drivermock.New()
		drv.LockErr = errors.New("lock failed")
		m := migrate.New(
			migrate.WithSource(sourcemock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Up(t.Context())
		assert.ErrorContains(t, err, "failed to acquire lock")
		assert.False(t, drv.IsLocked)
	})

	t.Run("error init fails", func(t *testing.T) {
		drv := drivermock.New()
		drv.InitErr = errors.New("table creation failed")
		m := migrate.New(
			migrate.WithSource(sourcemock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Up(t.Context())
		assert.ErrorContains(t, err, "failed to initialize driver")
		assert.False(t, drv.IsLocked, "lock must be released on init failure")
	})

	t.Run("error execution", func(t *testing.T) {
		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   []byte("err"),
			},
		)
		drv := drivermock.New()
		drv.ExecuteErr = errors.New("syntax error")
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		assert.ErrorContains(t, err, "migration 1 failed")
		assert.False(t, drv.IsLocked, "lock must be released on execute failure")
	})

	t.Run("error missing source file", func(t *testing.T) {
		src := sourcemock.New() // Empty
		drv := drivermock.New()
		drv.Set(migrate.Record{
			Version:  1,
			Checksum: sha256.Sum256([]byte("old content")),
		})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		msg := "applied migration 1 is missing from source files"
		assert.ErrorContains(t, err, msg)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("error checksum mismatch", func(t *testing.T) {
		oldContent := []byte("old content")
		newContent := []byte("new content")
		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   newContent,
			},
		)
		drv := drivermock.New()
		drv.Set(migrate.Record{
			Version:  1,
			Checksum: sha256.Sum256(oldContent),
		})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		assert.ErrorContains(t, err, "checksum mismatch")
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("error dirty state", func(t *testing.T) {
		content := []byte("content")
		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   content,
			},
		)
		drv := drivermock.New()
		drv.Set(migrate.Record{
			Version:  1,
			Checksum: sha256.Sum256(content),
			Dirty:    true,
		})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		assert.ErrorContains(t, err, "database is dirty at version 1")
		assert.False(t, drv.IsLocked, "lock must be released")
	})
}

func TestMigrator_Down(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		up := []byte("CREATE")
		down := []byte("DROP TABLE users;")

		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   up,
			},
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Down,
				Content:   down,
			},
		)
		drv := drivermock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(up)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Down(t.Context())
		assert.NoError(t, err)

		state := drv.State()
		assert.Empty(t, state)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("success no applied migrations", func(t *testing.T) {
		src := sourcemock.New()
		drv := drivermock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Down(t.Context())
		assert.NoError(t, err)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("error missing down script", func(t *testing.T) {
		content := []byte("CREATE")
		src := sourcemock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   content,
			},
		)
		drv := drivermock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Down(t.Context())
		assert.ErrorContains(t, err, "down migration file not found")
		assert.False(t, drv.IsLocked, "lock must be released")
	})
}

func TestMigrator_Force(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		drv := drivermock.New()
		m := migrate.New(
			migrate.WithSource(sourcemock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Force(t.Context(), 5)
		assert.NoError(t, err)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("error driver fails", func(t *testing.T) {
		drv := drivermock.New()
		drv.ForceErr = errors.New("db disconnected")
		m := migrate.New(
			migrate.WithSource(sourcemock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Force(t.Context(), 5)
		assert.ErrorContains(t, err, "failed to force version")
		assert.False(t, drv.IsLocked, "lock must be released")
	})
}

func TestMigrator_MigrateTo(t *testing.T) {
	content1 := []byte("CREATE t1")
	content2 := []byte("CREATE t2")
	content3 := []byte("DROP t2")
	content4 := []byte("CREATE t3")

	src := sourcemock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Content:   content1,
		},
		migrate.SourceScript{
			Version:   2,
			Direction: migrate.Up,
			Content:   content2,
		},
		migrate.SourceScript{
			Version:   2,
			Direction: migrate.Down,
			Content:   content3,
		},
		migrate.SourceScript{
			Version:   3,
			Direction: migrate.Up,
			Content:   content4,
		},
	)

	t.Run("apply pending", func(t *testing.T) {
		drv := drivermock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.MigrateTo(t.Context(), 3)
		assert.NoError(t, err)

		state := drv.State()
		assert.Len(t, state, 3)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("revert applied", func(t *testing.T) {
		drv := drivermock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.MigrateTo(t.Context(), 1)
		assert.NoError(t, err)

		state := drv.State()
		assert.Len(t, state, 1)
		_, ok := state[1]
		assert.True(t, ok)
		assert.False(t, drv.IsLocked, "lock must be released")
	})

	t.Run("error missing down script during revert", func(t *testing.T) {
		drv := drivermock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		drv.Set(migrate.Record{Version: 3, Checksum: sha256.Sum256(content4)})

		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.MigrateTo(t.Context(), 2)
		assert.ErrorContains(t, err, "down migration file not found for version 3")
		assert.False(t, drv.IsLocked, "lock must be released")
	})
}

func TestMigrator_Pending_And_Applied(t *testing.T) {
	content1 := []byte("1")
	content2 := []byte("2")
	content3 := []byte("3")

	src := sourcemock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Content:   content1,
		},
		migrate.SourceScript{
			Version:   2,
			Direction: migrate.Up,
			Content:   content2,
		},
		migrate.SourceScript{
			Version:   3,
			Direction: migrate.Up,
			Content:   content3,
		},
	)

	drv := drivermock.New()
	drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})

	m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

	pending, err := m.Pending(t.Context())
	require.NoError(t, err)
	assert.Len(t, pending, 2)
	assert.Equal(t, uint64(2), pending[0].Version)
	assert.Equal(t, uint64(3), pending[1].Version)

	applied, err := m.Applied(t.Context())
	require.NoError(t, err)
	assert.Len(t, applied, 1)
	assert.Equal(t, uint64(1), applied[0].Version)
}

func TestMigrator_DryRun(t *testing.T) {
	content := []byte("CREATE TABLE dummy;")
	src := sourcemock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Content:   content,
		},
	)
	drv := drivermock.New()
	m := migrate.New(
		migrate.WithSource(src),
		migrate.WithDriver(drv),
		migrate.WithDryRun(true),
	)

	err := m.Up(t.Context())
	assert.NoError(t, err)

	state := drv.State()
	assert.Empty(t, state)
	assert.False(t, drv.IsLocked, "lock must be released")
}

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

func TestMigrator_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db := setup(t)

	fsys := fstest.MapFS{
		"01_init.up.sql": &fstest.MapFile{
			Data: []byte(
				"CREATE TABLE integration_users (id SERIAL PRIMARY KEY, name TEXT);",
			),
		},
		"01_init.down.sql": &fstest.MapFile{
			Data: []byte(
				"DROP TABLE integration_users;",
			),
		},
		"02_seed.up.sql": &fstest.MapFile{
			Data: []byte(
				"INSERT INTO integration_users (name) VALUES ('Alice'), ('Bob');",
			),
		},
		"02_seed.down.sql": &fstest.MapFile{
			Data: []byte(
				"TRUNCATE TABLE integration_users;",
			),
		},
	}

	src := file.New(fsys)
	drv := postgres.New(db)

	m := migrate.New(
		migrate.WithSource(src),
		migrate.WithDriver(drv),
	)

	err := m.Up(t.Context())
	require.NoError(t, err, "up migrations should apply successfully")

	var count int
	err = db.QueryRowContext(
		t.Context(),
		"SELECT count(*) FROM integration_users",
	).Scan(&count)

	require.NoError(t, err, "table should exist and be queryable")
	assert.Equal(t, 2, count, "table should contain the seeded records")

	applied, err := m.Applied(t.Context())
	require.NoError(t, err)
	assert.Len(t, applied, 2, "tracking table should reflect applied migrations")

	err = m.Down(t.Context())
	require.NoError(t, err, "down migration should execute successfully")

	err = db.QueryRowContext(
		t.Context(),
		"SELECT count(*) FROM integration_users",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "table should be empty after reverting seed")

	err = m.Down(t.Context())
	require.NoError(t, err)

	err = db.QueryRowContext(
		t.Context(),
		"SELECT count(*) FROM integration_users",
	).Scan(&count)
	assert.ErrorContains(
		t,
		err,
		"relation \"integration_users\" does not exist",
		"query should fail on dropped table",
	)

	applied, err = m.Applied(t.Context())
	require.NoError(t, err)
	assert.Empty(
		t,
		applied,
		"tracking table should be empty after all down migrations",
	)
}
