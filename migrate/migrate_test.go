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
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/migrate"
	drvmock "github.com/deep-rent/nexus/migrate/driver/mock"
	"github.com/deep-rent/nexus/migrate/driver/postgres"
	"github.com/deep-rent/nexus/migrate/source/file"
	srcmock "github.com/deep-rent/nexus/migrate/source/mock"
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
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drvmock.New()),
		)
		if m == nil {
			t.Fatal("migrate.New() = nil; want non-nil")
		}
	})

	t.Run("panic missing source", func(t *testing.T) {
		t.Parallel()
		want := "migrate: source is required"
		defer func() {
			if r := recover(); r != want {
				t.Errorf("recover() = %v; want %q", r, want)
			}
		}()
		migrate.New(migrate.WithDriver(drvmock.New()))
	})

	t.Run("panic missing driver", func(t *testing.T) {
		t.Parallel()
		want := "migrate: driver is required"
		defer func() {
			if r := recover(); r != want {
				t.Errorf("recover() = %v; want %q", r, want)
			}
		}()
		migrate.New(migrate.WithSource(srcmock.New()))
	})
}

func TestMigrator_Up(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		up1 := []byte("CREATE TABLE users;")
		up2 := []byte("CREATE TABLE posts;")

		src := srcmock.New(
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
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Up(t.Context()); err != nil {
			t.Fatalf("Up() err = %v; want nil", err)
		}

		state := drv.State()
		if len(state) != 2 {
			t.Errorf("len(state) = %d; want 2", len(state))
		}
		if state[1].Checksum != sha256.Sum256(up1) {
			t.Errorf("version 1 checksum mismatch")
		}
		if state[2].Checksum != sha256.Sum256(up2) {
			t.Errorf("version 2 checksum mismatch")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("success up to date", func(t *testing.T) {
		t.Parallel()
		up := []byte("CREATE TABLE users;")
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   up,
			},
		)
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(up)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Up(t.Context()); err != nil {
			t.Errorf("Up() err = %v; want nil", err)
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("error locked", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.LockErr = errors.New("lock failed")
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("Up() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("IsLocked = true; want false")
		}
	})

	t.Run("error init fails", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.InitErr = errors.New("table creation failed")
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("Up() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released on init failure")
		}
	})

	t.Run("error execution", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   []byte("err"),
			},
		)
		drv := drvmock.New()
		drv.ExecuteErr = errors.New("syntax error")
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("Up() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released on execute failure")
		}
	})

	t.Run("error missing source file", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New()
		drv := drvmock.New()
		drv.Set(migrate.Record{
			Version:  1,
			Checksum: sha256.Sum256([]byte("old content")),
		})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("Up() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("error checksum mismatch", func(t *testing.T) {
		t.Parallel()
		oldContent := []byte("old content")
		newContent := []byte("new content")
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   newContent,
			},
		)
		drv := drvmock.New()
		drv.Set(migrate.Record{
			Version:  1,
			Checksum: sha256.Sum256(oldContent),
		})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("Up() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("error dirty state", func(t *testing.T) {
		t.Parallel()
		content := []byte("content")
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   content,
			},
		)
		drv := drvmock.New()
		drv.Set(migrate.Record{
			Version:  1,
			Checksum: sha256.Sum256(content),
			Dirty:    true,
		})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("Up() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})
}

func TestMigrator_Down(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		up := []byte("CREATE")
		down := []byte("DROP TABLE users;")

		src := srcmock.New(
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
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(up)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Down(t.Context()); err != nil {
			t.Errorf("Down() err = %v; want nil", err)
		}

		if len(drv.State()) != 0 {
			t.Errorf("len(state) = %d; want 0", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("success no applied migrations", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New()
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Down(t.Context()); err != nil {
			t.Errorf("Down() err = %v; want nil", err)
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("error missing down script", func(t *testing.T) {
		t.Parallel()
		content := []byte("CREATE")
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   content,
			},
		)
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Down(t.Context())
		if err == nil {
			t.Fatal("Down() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})
}

func TestMigrator_Force(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		if err := m.Force(t.Context(), 5); err != nil {
			t.Errorf("Force() err = %v; want nil", err)
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("error driver fails", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.ForceErr = errors.New("db disconnected")
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		err := m.Force(t.Context(), 5)
		if err == nil {
			t.Fatal("Force() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})
}

func TestMigrator_MigrateTo(t *testing.T) {
	t.Parallel()

	content1 := []byte("CREATE t1")
	content2 := []byte("CREATE t2")
	content3 := []byte("DROP t2")
	content4 := []byte("CREATE t3")

	src := srcmock.New(
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
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.MigrateTo(t.Context(), 3); err != nil {
			t.Errorf("MigrateTo(3) err = %v; want nil", err)
		}

		if len(drv.State()) != 3 {
			t.Errorf("len(state) = %d; want 3", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("revert applied", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.MigrateTo(t.Context(), 1); err != nil {
			t.Errorf("MigrateTo(1) err = %v; want nil", err)
		}

		state := drv.State()
		if len(state) != 1 {
			t.Errorf("len(state) = %d; want 1", len(state))
		}
		if _, ok := state[1]; !ok {
			t.Error("version 1 missing from state")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})

	t.Run("error missing down script during revert", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		drv.Set(migrate.Record{Version: 3, Checksum: sha256.Sum256(content4)})

		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.MigrateTo(t.Context(), 2)
		if err == nil {
			t.Fatal("MigrateTo() = nil; want error")
		}
		if drv.IsLocked {
			t.Error("lock not released")
		}
	})
}

func TestMigrator_Pending_And_Applied(t *testing.T) {
	t.Parallel()

	content1 := []byte("1")
	content2 := []byte("2")
	content3 := []byte("3")

	src := srcmock.New(
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

	drv := drvmock.New()
	drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})

	m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

	pending, err := m.Pending(t.Context())
	if err != nil {
		t.Fatalf("Pending() err = %v; want nil", err)
	}
	if len(pending) != 2 {
		t.Errorf("len(pending) = %d; want 2", len(pending))
	}
	if pending[0].Version != 2 || pending[1].Version != 3 {
		t.Errorf("pending versions = [%d, %d]; want [2, 3]",
			pending[0].Version, pending[1].Version)
	}

	applied, err := m.Applied(t.Context())
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if len(applied) != 1 {
		t.Errorf("len(applied) = %d; want 1", len(applied))
	}
	if applied[0].Version != 1 {
		t.Errorf("applied[0].Version = %d; want 1", applied[0].Version)
	}
}

func TestMigrator_DryRun(t *testing.T) {
	t.Parallel()

	content := []byte("CREATE TABLE dummy;")
	src := srcmock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Content:   content,
		},
	)
	drv := drvmock.New()
	m := migrate.New(
		migrate.WithSource(src),
		migrate.WithDriver(drv),
		migrate.WithDryRun(true),
	)

	if err := m.Up(t.Context()); err != nil {
		t.Errorf("Up() err = %v; want nil", err)
	}

	if len(drv.State()) != 0 {
		t.Errorf("len(state) = %d; want 0", len(drv.State()))
	}
	if drv.IsLocked {
		t.Error("lock not released")
	}
}

func TestMigrator_Integration(t *testing.T) {
	t.Parallel()

	db := setupDB(t)

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
	ctx := context.Background()

	m := migrate.New(
		migrate.WithSource(src),
		migrate.WithDriver(drv),
	)

	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up() err = %v; want nil", err)
	}

	var count int
	query := "SELECT count(*) FROM integration_users"
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d; want 2", count)
	}

	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if len(applied) != 2 {
		t.Errorf("len(applied) = %d; want 2", len(applied))
	}

	if err := m.Down(ctx); err != nil {
		t.Fatalf("Down() err = %v; want nil", err)
	}

	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d; want 0", count)
	}

	if err := m.Down(ctx); err != nil {
		t.Fatalf("Down() #2 err = %v; want nil", err)
	}

	err = db.QueryRowContext(ctx, query).Scan(&count)
	if err == nil {
		t.Error("query succeeded; want error on dropped table")
	}

	applied, err = m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() err = %v; want nil", err)
	}
	if len(applied) != 0 {
		t.Errorf("len(applied) = %d; want 0", len(applied))
	}
}
