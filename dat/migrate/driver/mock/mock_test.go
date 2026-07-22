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
	"errors"
	"testing"

	"github.com/deep-rent/nexus/dat/migrate"
	"github.com/deep-rent/nexus/dat/migrate/driver/mock"
)

func TestNewDriver(t *testing.T) {
	t.Parallel()

	d := mock.New()
	if d == nil {
		t.Fatal("driver: got nil; want non-nil")
	}
	if d.State() == nil {
		t.Error("state: got nil; want non-nil")
	}
	if d.ParserFunc == nil {
		t.Error("parser func: got nil; want non-nil")
	}

	parser := d.Parser()
	if got := parser(nil); got != nil {
		t.Errorf("for nil input: got %v; want nil", got)
	}
	if got := parser([]byte{}); got != nil {
		t.Errorf("for empty input: got %v; want nil", got)
	}

	want := []string{"statement"}
	got := parser([]byte("statement"))
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("for a single statement: got %v; want %v", got, want)
	}
}

func TestDriver_Init(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		if err := d.Init(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if !d.IsInit {
			t.Error("init flag: got false; want true")
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		want := errors.New("init failed")
		d.InitErr = want
		if err := d.Init(t.Context()); !errors.Is(err, want) {
			t.Errorf("error: got %v; want %v", err, want)
		}
		if d.IsInit {
			t.Error("init flag: got true; want false")
		}
	})
}

func TestDriver_Lock(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		if err := d.Lock(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if !d.IsLocked {
			t.Error("lock flag: got false; want true")
		}
	})

	t.Run("error injected", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		want := errors.New("lock failed")
		d.LockErr = want
		if err := d.Lock(t.Context()); !errors.Is(err, want) {
			t.Errorf("error: got %v; want %v", err, want)
		}
		if d.IsLocked {
			t.Error("lock flag: got true; want false")
		}
	})

	t.Run("already locked", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		_ = d.Lock(t.Context())

		want := "already locked"
		if err := d.Lock(t.Context()); err == nil || err.Error() != want {
			t.Errorf("on second call: got %v; want %q", err, want)
		}
	})
}

func TestDriver_Unlock(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		d.IsLocked = true
		if err := d.Unlock(t.Context()); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
		if d.IsLocked {
			t.Error("lock flag: got true; want false")
		}
	})

	t.Run("error injected", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		d.IsLocked = true
		want := errors.New("unlock failed")
		d.UnlockErr = want
		if err := d.Unlock(t.Context()); !errors.Is(err, want) {
			t.Errorf("error: got %v; want %v", err, want)
		}
		if !d.IsLocked {
			t.Error("lock flag: got false; want true")
		}
	})

	t.Run("not locked", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		want := "not locked"
		if err := d.Unlock(t.Context()); err == nil || err.Error() != want {
			t.Errorf("got %v; want %q", err, want)
		}
	})
}

func TestDriver_Applied(t *testing.T) {
	t.Parallel()

	t.Run("success sorted", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		d.Set(migrate.Record{Version: 3})
		d.Set(migrate.Record{Version: 1})
		d.Set(migrate.Record{Version: 2})

		records, err := d.Applied(t.Context())
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if got, want := len(records), 3; got != want {
			t.Fatalf("got size %d; want %d", got, want)
		}
		v1 := records[0].Version
		v2 := records[1].Version
		v3 := records[2].Version
		if v1 != 1 || v2 != 2 || v3 != 3 {
			t.Errorf(
				"version order: got [%d, %d, %d]; want [1, 2, 3]",
				v1, v2, v3,
			)
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		want := errors.New("applied failed")
		d.AppliedErr = want
		records, err := d.Applied(t.Context())
		if !errors.Is(err, want) {
			t.Errorf("error: got %v; want %v", err, want)
		}
		if records != nil {
			t.Errorf("records: got %v; want nil", records)
		}
	})
}

func TestDriver_Force(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		d.Set(migrate.Record{Version: 1, Dirty: false})
		d.Set(migrate.Record{Version: 2, Dirty: true})
		d.Set(migrate.Record{Version: 3, Dirty: false})

		if err := d.Force(t.Context(), 2); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}

		state := d.State()
		if len(state) != 2 {
			t.Errorf("state size: got %d; want 2", len(state))
		}
		if state[1].Dirty {
			t.Error("dirty flag at version 1: got true; want false")
		}
		if state[2].Dirty {
			t.Error("dirty flag at version 2: got true; want false")
		}
		if _, exists := state[3]; exists {
			t.Error("version 3 should have been removed from the state")
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()
		d := mock.New()
		want := errors.New("force failed")
		d.ForceErr = want
		if err := d.Force(t.Context(), 1); !errors.Is(err, want) {
			t.Errorf("got %v; want %v", err, want)
		}
	})
}

func TestDriver_Execute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(*mock.Driver)
		script   migrate.ParsedScript
		giveErr  error
		validate func(*testing.T, *mock.Driver)
	}{
		{
			name: "up success",
			script: migrate.ParsedScript{
				Version:   1,
				Direction: migrate.Up,
				Checksum:  [32]byte{1, 2, 3},
			},
			validate: func(t *testing.T, d *mock.Driver) {
				t.Helper()
				rec, ok := d.Get(1)
				if !ok {
					t.Fatal("version 1 not found in the state")
				}
				if rec.Version != 1 {
					t.Errorf("version: got %d; want 1", rec.Version)
				}
				if rec.Checksum != [32]byte{1, 2, 3} {
					t.Error("checksum mismatch")
				}
				if rec.Dirty {
					t.Error("dirty flag: got true; want false")
				}
			},
		},
		{
			name:    "up error",
			giveErr: errors.New("execute error"),
			script: migrate.ParsedScript{
				Version:   2,
				Direction: migrate.Up,
				Checksum:  [32]byte{4, 5, 6},
			},
			validate: func(t *testing.T, d *mock.Driver) {
				t.Helper()
				rec, ok := d.Get(2)
				if !ok {
					t.Fatal("version 2 not found in the state")
				}
				if rec.Version != 2 {
					t.Errorf("version: got %d; want 2", rec.Version)
				}
				if !rec.Dirty {
					t.Error("dirty flag: got false; want true")
				}
			},
		},
		{
			name:    "up error transactional",
			giveErr: errors.New("execute error"),
			script: migrate.ParsedScript{
				Version:   2,
				Direction: migrate.Up,
				Checksum:  [32]byte{4, 5, 6},
				Tx:        true,
			},
			validate: func(t *testing.T, d *mock.Driver) {
				t.Helper()
				if _, ok := d.Get(2); ok {
					t.Error("version 2 should not be recorded after rollback")
				}
			},
		},
		{
			name: "down error transactional",
			setup: func(d *mock.Driver) {
				d.Set(migrate.Record{Version: 4, Dirty: false})
			},
			giveErr: errors.New("execute error"),
			script: migrate.ParsedScript{
				Version:   4,
				Direction: migrate.Down,
				Tx:        true,
			},
			validate: func(t *testing.T, d *mock.Driver) {
				t.Helper()
				rec, ok := d.Get(4)
				if !ok {
					t.Fatal("version 4 not found in the state")
				}
				if rec.Dirty {
					t.Error("dirty flag: got true; want false after rollback")
				}
			},
		},
		{
			name: "down success",
			setup: func(d *mock.Driver) {
				d.Set(migrate.Record{Version: 3})
			},
			script: migrate.ParsedScript{
				Version:   3,
				Direction: migrate.Down,
			},
			validate: func(t *testing.T, d *mock.Driver) {
				t.Helper()
				if _, ok := d.Get(3); ok {
					t.Error("version 3 should have been removed from the state")
				}
			},
		},
		{
			name: "down error",
			setup: func(d *mock.Driver) {
				d.Set(migrate.Record{Version: 4, Dirty: false})
			},
			giveErr: errors.New("execute error"),
			script: migrate.ParsedScript{
				Version:   4,
				Direction: migrate.Down,
			},
			validate: func(t *testing.T, d *mock.Driver) {
				t.Helper()
				rec, ok := d.Get(4)
				if !ok {
					t.Fatal("version 4 not found in the state")
				}
				if !rec.Dirty {
					t.Error("dirty flag: got false; want true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := mock.New()
			if tt.setup != nil {
				tt.setup(d)
			}
			d.ExecuteErr = tt.giveErr

			err := d.Execute(t.Context(), tt.script)
			if tt.giveErr != nil {
				if !errors.Is(err, tt.giveErr) {
					t.Errorf("error: got %v; want %v", err, tt.giveErr)
				}
			} else if err != nil {
				t.Errorf("should not have returned an error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, d)
			}
		})
	}
}
