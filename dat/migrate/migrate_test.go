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

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	testpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/deep-rent/nexus/dat/migrate"
	drvmock "github.com/deep-rent/nexus/dat/migrate/driver/mock"
	"github.com/deep-rent/nexus/dat/migrate/driver/postgres"
	"github.com/deep-rent/nexus/dat/migrate/source/file"
	srcmock "github.com/deep-rent/nexus/dat/migrate/source/mock"
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

func TestDirection_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		give migrate.Direction
		want string
	}{
		{migrate.Up, "up"},
		{migrate.Down, "down"},
		{migrate.Direction(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.give.String(); got != tt.want {
			t.Errorf("for %d: got %q; want %q", int(tt.give), got, tt.want)
		}
	}
}

func TestMigration_Compare(t *testing.T) {
	t.Parallel()

	up1 := migrate.Migration{Version: 1, Direction: migrate.Up}
	down1 := migrate.Migration{Version: 1, Direction: migrate.Down}
	up2 := migrate.Migration{Version: 2, Direction: migrate.Up}

	if got := up1.Compare(up2); got >= 0 {
		t.Errorf("lower version: got %d; want negative", got)
	}
	if got := up2.Compare(up1); got <= 0 {
		t.Errorf("higher version: got %d; want positive", got)
	}
	if got := up1.Compare(up1); got != 0 {
		t.Errorf("equal migrations: got %d; want 0", got)
	}
	// Up sorts before down at the same version.
	if got := up1.Compare(down1); got >= 0 {
		t.Errorf("up vs down: got %d; want negative", got)
	}
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
			t.Fatal("got nil; want non-nil")
		}
	})

	t.Run("panic missing source", func(t *testing.T) {
		t.Parallel()
		want := "source is required"
		defer func() {
			if r := recover(); r != want {
				t.Errorf("got %v; want %q", r, want)
			}
		}()
		migrate.New(migrate.WithDriver(drvmock.New()))
	})

	t.Run("panic missing driver", func(t *testing.T) {
		t.Parallel()
		want := "driver is required"
		defer func() {
			if r := recover(); r != want {
				t.Errorf("got %v; want %q", r, want)
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
			t.Fatalf("should not have returned an error: %v", err)
		}

		state := drv.State()
		if len(state) != 2 {
			t.Errorf("state size: got %d; want 2", len(state))
		}
		if state[1].Checksum != sha256.Sum256(up1) {
			t.Error("checksum mismatch at version 1")
		}
		if state[2].Checksum != sha256.Sum256(up2) {
			t.Error("checksum mismatch at version 2")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Errorf("should not have returned an error: %v", err)
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("error source list fails", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New()
		src.ListErr = errors.New("storage unreachable")
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("unlock error is not returned", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   []byte("CREATE TABLE users;"),
			},
		)
		drv := drvmock.New()
		drv.UnlockErr = errors.New("connection lost")
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		// A failed unlock is logged but must not fail an otherwise
		// successful migration run.
		if err := m.Up(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 1 {
			t.Errorf("state size: got %d; want 1", len(drv.State()))
		}
	})

	t.Run("error duplicate version", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Path:      "1_a.up.sql",
				Content:   []byte("CREATE a;"),
			},
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Path:      "01_b.up.sql",
				Content:   []byte("CREATE b;"),
			},
		)
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("should have returned an error")
		}
		if len(drv.State()) != 0 {
			t.Errorf("state size: got %d; want 0", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})
}

func TestMigrator_StrictOrder(t *testing.T) {
	t.Parallel()

	content1 := []byte("CREATE t1")
	content2 := []byte("CREATE t2")
	content3 := []byte("CREATE t3")

	src := srcmock.New(
		migrate.SourceScript{
			Version:   1,
			Direction: migrate.Up,
			Path:      "1_a.up.sql",
			Content:   content1,
		},
		migrate.SourceScript{
			Version:   2,
			Direction: migrate.Up,
			Path:      "2_b.up.sql",
			Content:   content2,
		},
		migrate.SourceScript{
			Version:   3,
			Direction: migrate.Up,
			Path:      "3_c.up.sql",
			Content:   content3,
		},
	)

	t.Run("error out of order", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		// Version 3 is applied, but 1 and 2 are still pending.
		drv.Set(migrate.Record{Version: 3, Checksum: sha256.Sum256(content3)})
		m := migrate.New(
			migrate.WithSource(src),
			migrate.WithDriver(drv),
			migrate.WithStrictOrder(true),
		)

		err := m.Up(t.Context())
		if err == nil {
			t.Fatal("should have returned an error")
		}
		if len(drv.State()) != 1 {
			t.Errorf("state size: got %d; want 1", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("success in order", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		m := migrate.New(
			migrate.WithSource(src),
			migrate.WithDriver(drv),
			migrate.WithStrictOrder(true),
		)

		if err := m.Up(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 3 {
			t.Errorf("state size: got %d; want 3", len(drv.State()))
		}
	})

	t.Run("lenient by default", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 3, Checksum: sha256.Sum256(content3)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Up(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 3 {
			t.Errorf("state size: got %d; want 3", len(drv.State()))
		}
	})

	t.Run("error out of order via migrate to", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 3, Checksum: sha256.Sum256(content3)})
		m := migrate.New(
			migrate.WithSource(src),
			migrate.WithDriver(drv),
			migrate.WithStrictOrder(true),
		)

		err := m.MigrateTo(t.Context(), 3)
		if err == nil {
			t.Fatal("should have returned an error")
		}
		if len(drv.State()) != 1 {
			t.Errorf("state size: got %d; want 1", len(drv.State()))
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
			t.Errorf("should not have returned an error: %v", err)
		}

		if len(drv.State()) != 0 {
			t.Errorf("state size: got %d; want 0", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("success no applied migrations", func(t *testing.T) {
		t.Parallel()
		src := srcmock.New()
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Down(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Errorf("should not have returned an error: %v", err)
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
			t.Errorf("should not have returned an error: %v", err)
		}

		if len(drv.State()) != 3 {
			t.Errorf("state size: got %d; want 3", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("revert applied", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.MigrateTo(t.Context(), 1); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}

		state := drv.State()
		if len(state) != 1 {
			t.Errorf("state size: got %d; want 1", len(state))
		}
		if _, ok := state[1]; !ok {
			t.Error("version 1 missing from the state")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("revert all to zero", func(t *testing.T) {
		t.Parallel()
		content5 := []byte("DROP t1")
		full := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   content1,
			},
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Down,
				Content:   content5,
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
		)
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		m := migrate.New(migrate.WithSource(full), migrate.WithDriver(drv))

		if err := m.MigrateTo(t.Context(), 0); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 0 {
			t.Errorf("state size: got %d; want 0", len(drv.State()))
		}
	})

	t.Run("no-op at target", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.MigrateTo(t.Context(), 2); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 2 {
			t.Errorf("state size: got %d; want 2", len(drv.State()))
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
			t.Fatal("should have returned an error")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
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
		t.Fatalf("pending: should not have returned an error: %v", err)
	}
	if !drv.IsInit {
		t.Error("pending: should have initialized the tracking table")
	}
	if len(pending) != 2 {
		t.Errorf("pending size: got %d; want 2", len(pending))
	}
	if pending[0].Version != 2 || pending[1].Version != 3 {
		t.Errorf("pending versions: got [%d, %d]; want [2, 3]",
			pending[0].Version, pending[1].Version)
	}

	applied, err := m.Applied(t.Context())
	if err != nil {
		t.Fatalf("applied: should not have returned an error: %v", err)
	}
	if len(applied) != 1 {
		t.Errorf("applied size: got %d; want 1", len(applied))
	}
	if applied[0].Version != 1 {
		t.Errorf(
			"applied at index 0: got version %d; want 1",
			applied[0].Version,
		)
	}
}

func TestMigrator_Steps(t *testing.T) {
	t.Parallel()

	content1 := []byte("CREATE t1")
	content2 := []byte("CREATE t2")
	content3 := []byte("DROP t1")
	content4 := []byte("DROP t2")

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
			Version:   1,
			Direction: migrate.Down,
			Content:   content3,
		},
		migrate.SourceScript{
			Version:   2,
			Direction: migrate.Down,
			Content:   content4,
		},
	)

	t.Run("apply limited", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Steps(t.Context(), 1); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}

		state := drv.State()
		if len(state) != 1 {
			t.Fatalf("state size: got %d; want 1", len(state))
		}
		if _, ok := state[1]; !ok {
			t.Error("version 1 missing from the state")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("apply more than available", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Steps(t.Context(), 10); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 2 {
			t.Errorf("state size: got %d; want 2", len(drv.State()))
		}
	})

	t.Run("revert limited", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		drv.Set(migrate.Record{Version: 2, Checksum: sha256.Sum256(content2)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Steps(t.Context(), -1); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}

		state := drv.State()
		if len(state) != 1 {
			t.Fatalf("state size: got %d; want 1", len(state))
		}
		if _, ok := state[1]; !ok {
			t.Error("version 1 missing from the state")
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("revert more than available", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Steps(t.Context(), -5); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if len(drv.State()) != 0 {
			t.Errorf("state size: got %d; want 0", len(drv.State()))
		}
	})

	t.Run("zero is a no-op", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(migrate.WithSource(src), migrate.WithDriver(drv))

		if err := m.Steps(t.Context(), 0); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if drv.IsInit {
			t.Error("zero steps should not have touched the driver")
		}
	})

	t.Run("error missing down script", func(t *testing.T) {
		t.Parallel()
		noDowns := srcmock.New(
			migrate.SourceScript{
				Version:   1,
				Direction: migrate.Up,
				Content:   content1,
			},
		)
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(content1)})
		m := migrate.New(migrate.WithSource(noDowns), migrate.WithDriver(drv))

		if err := m.Steps(t.Context(), -1); err == nil {
			t.Error("should have returned an error")
		}
	})
}

func TestMigrator_Version(t *testing.T) {
	t.Parallel()

	t.Run("empty database", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		_, ok, err := m.Version(t.Context())
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if ok {
			t.Error("ok: got true; want false")
		}
		if !drv.IsInit {
			t.Error("should have initialized the tracking table")
		}
	})

	t.Run("latest applied", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1})
		drv.Set(migrate.Record{Version: 2})
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		rec, ok, err := m.Version(t.Context())
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if !ok {
			t.Fatal("ok: got false; want true")
		}
		if rec.Version != 2 {
			t.Errorf("version: got %d; want 2", rec.Version)
		}
	})

	t.Run("dirty database", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 4, Dirty: true})
		// No source files exist for version 4; Version must not verify.
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		rec, ok, err := m.Version(t.Context())
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if !ok {
			t.Fatal("ok: got false; want true")
		}
		if !rec.Dirty {
			t.Error("dirty: got false; want true")
		}
	})

	t.Run("error applied fails", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.AppliedErr = errors.New("db down")
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		if _, _, err := m.Version(t.Context()); err == nil {
			t.Error("should have returned an error")
		}
	})

	t.Run("error init fails", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.InitErr = errors.New("no permissions")
		m := migrate.New(
			migrate.WithSource(srcmock.New()),
			migrate.WithDriver(drv),
		)

		if _, _, err := m.Version(t.Context()); err == nil {
			t.Error("should have returned an error")
		}
	})
}

func TestMigrator_DryRun(t *testing.T) {
	t.Parallel()

	up := []byte("CREATE TABLE dummy;")
	down := []byte("DROP TABLE dummy;")
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

	t.Run("up", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(
			migrate.WithSource(src),
			migrate.WithDriver(drv),
			migrate.WithDryRun(true),
		)

		if err := m.Up(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}

		if len(drv.State()) != 0 {
			t.Errorf("state size: got %d; want 0", len(drv.State()))
		}
		if drv.IsLocked {
			t.Error("lock was not released")
		}
	})

	t.Run("down", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		drv.Set(migrate.Record{Version: 1, Checksum: sha256.Sum256(up)})
		m := migrate.New(
			migrate.WithSource(src),
			migrate.WithDriver(drv),
			migrate.WithDryRun(true),
		)

		if err := m.Down(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}

		if len(drv.State()) != 1 {
			t.Errorf("state size: got %d; want 1", len(drv.State()))
		}
	})

	t.Run("migrate to", func(t *testing.T) {
		t.Parallel()
		drv := drvmock.New()
		m := migrate.New(
			migrate.WithSource(src),
			migrate.WithDriver(drv),
			migrate.WithDryRun(true),
		)

		if err := m.MigrateTo(t.Context(), 1); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}

		if len(drv.State()) != 0 {
			t.Errorf("state size: got %d; want 0", len(drv.State()))
		}
	})
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

	// Status queries must work against a pristine database, before any
	// migration has created the tracking table.
	pending, err := m.Pending(ctx)
	if err != nil {
		t.Fatalf(
			"pending on fresh db: should not have returned an error: %v",
			err,
		)
	}
	if len(pending) != 2 {
		t.Errorf("on fresh db: got pending size %d; want 2", len(pending))
	}

	if err := m.Up(ctx); err != nil {
		t.Fatalf("on up: should not have returned an error: %v", err)
	}

	var count int
	query := "SELECT count(*) FROM integration_users"
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		t.Fatalf(
			"querying after up: should not have returned an error: %v",
			err,
		)
	}
	if count != 2 {
		t.Errorf("after up: got count %d; want 2", count)
	}

	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("applied after up: should not have returned an error: %v", err)
	}
	if len(applied) != 2 {
		t.Errorf("after up: got applied size %d; want 2", len(applied))
	}

	if err := m.Down(ctx); err != nil {
		t.Fatalf("on down: should not have returned an error: %v", err)
	}

	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		t.Fatalf(
			"querying after down: should not have returned an error: %v",
			err,
		)
	}
	if count != 0 {
		t.Errorf("after down: got count %d; want 0", count)
	}

	if err := m.Down(ctx); err != nil {
		t.Fatalf("on second down: should not have returned an error: %v", err)
	}

	err = db.QueryRowContext(ctx, query).Scan(&count)
	if err == nil {
		t.Error("querying the dropped table should have returned an error")
	}

	applied, err = m.Applied(ctx)
	if err != nil {
		t.Fatalf(
			"applied after second down: should not have returned an error: %v",
			err,
		)
	}
	if len(applied) != 0 {
		t.Errorf("after second down: got applied size %d; want 0", len(applied))
	}
}
