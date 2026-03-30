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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/driver/mock"
)

func TestNewDriver(t *testing.T) {
	d := mock.New()
	require.NotNil(t, d)
	require.NotNil(t, d.State())
	require.NotNil(t, d.ParserFunc)

	parser := d.Parser()
	assert.Nil(t, parser(nil))
	assert.Nil(t, parser([]byte{}))
	assert.Equal(t, []string{"statement"}, parser([]byte("statement")))
}

func TestDriver_Init(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := mock.New()
		err := d.Init(context.Background())
		assert.NoError(t, err)
		assert.True(t, d.IsInit)
	})

	t.Run("error", func(t *testing.T) {
		d := mock.New()
		expected := errors.New("init failed")
		d.InitErr = expected
		err := d.Init(context.Background())
		assert.ErrorIs(t, err, expected)
		assert.False(t, d.IsInit)
	})
}

func TestDriver_Lock(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := mock.New()
		err := d.Lock(context.Background())
		assert.NoError(t, err)
		assert.True(t, d.IsLocked)
	})

	t.Run("error injected", func(t *testing.T) {
		d := mock.New()
		expected := errors.New("lock failed")
		d.LockErr = expected
		err := d.Lock(context.Background())
		assert.ErrorIs(t, err, expected)
		assert.False(t, d.IsLocked)
	})

	t.Run("already locked", func(t *testing.T) {
		d := mock.New()
		err := d.Lock(context.Background())
		require.NoError(t, err)

		err = d.Lock(context.Background())
		assert.EqualError(t, err, "mock: already locked")
	})
}

func TestDriver_Unlock(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := mock.New()
		d.IsLocked = true
		err := d.Unlock(context.Background())
		assert.NoError(t, err)
		assert.False(t, d.IsLocked)
	})

	t.Run("error injected", func(t *testing.T) {
		d := mock.New()
		d.IsLocked = true
		expected := errors.New("unlock failed")
		d.UnlockErr = expected
		err := d.Unlock(context.Background())
		assert.ErrorIs(t, err, expected)
		assert.True(t, d.IsLocked)
	})

	t.Run("not locked", func(t *testing.T) {
		d := mock.New()
		err := d.Unlock(context.Background())
		assert.EqualError(t, err, "mock: not locked")
	})
}

func TestDriver_Applied(t *testing.T) {
	t.Run("success sorted", func(t *testing.T) {
		d := mock.New()
		d.Set(migrate.Record{Version: 3})
		d.Set(migrate.Record{Version: 1})
		d.Set(migrate.Record{Version: 2})

		records, err := d.Applied(context.Background())
		require.NoError(t, err)
		require.Len(t, records, 3)
		assert.Equal(t, uint64(1), records[0].Version)
		assert.Equal(t, uint64(2), records[1].Version)
		assert.Equal(t, uint64(3), records[2].Version)
	})

	t.Run("error", func(t *testing.T) {
		d := mock.New()
		expected := errors.New("applied failed")
		d.AppliedErr = expected
		records, err := d.Applied(context.Background())
		assert.ErrorIs(t, err, expected)
		assert.Nil(t, records)
	})
}

func TestDriver_Force(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := mock.New()
		d.Set(migrate.Record{Version: 1, Dirty: false})
		d.Set(migrate.Record{Version: 2, Dirty: true})
		d.Set(migrate.Record{Version: 3, Dirty: false})

		err := d.Force(context.Background(), 2)
		assert.NoError(t, err)

		state := d.State()
		assert.Len(t, state, 2)
		assert.False(t, state[1].Dirty)
		assert.False(t, state[2].Dirty)
		_, exists := state[3]
		assert.False(t, exists)
	})

	t.Run("error", func(t *testing.T) {
		d := mock.New()
		expected := errors.New("force failed")
		d.ForceErr = expected
		err := d.Force(context.Background(), 1)
		assert.ErrorIs(t, err, expected)
	})
}

func TestDriver_Execute(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*mock.Driver)
		script   migrate.ParsedScript
		err      error
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
				rec, ok := d.Get(1)
				require.True(t, ok)
				assert.Equal(t, uint64(1), rec.Version)
				assert.Equal(t, [32]byte{1, 2, 3}, rec.Checksum)
				assert.False(t, rec.Dirty)
			},
		},
		{
			name: "up error",
			err:  errors.New("execute error"),
			script: migrate.ParsedScript{
				Version:   2,
				Direction: migrate.Up,
				Checksum:  [32]byte{4, 5, 6},
			},
			validate: func(t *testing.T, d *mock.Driver) {
				rec, ok := d.Get(2)
				require.True(t, ok)
				assert.Equal(t, uint64(2), rec.Version)
				assert.True(t, rec.Dirty)
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
				_, ok := d.Get(3)
				assert.False(t, ok)
			},
		},
		{
			name: "down error",
			setup: func(d *mock.Driver) {
				d.Set(migrate.Record{Version: 4, Dirty: false})
			},
			err: errors.New("execute error"),
			script: migrate.ParsedScript{
				Version:   4,
				Direction: migrate.Down,
			},
			validate: func(t *testing.T, d *mock.Driver) {
				rec, ok := d.Get(4)
				require.True(t, ok)
				assert.True(t, rec.Dirty)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mock.New()
			if tc.setup != nil {
				tc.setup(d)
			}
			d.ExecuteErr = tc.err

			err := d.Execute(context.Background(), tc.script)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}

			if tc.validate != nil {
				tc.validate(t, d)
			}
		})
	}
}

func TestDriver_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d := mock.New()
		err := d.Close()
		assert.NoError(t, err)
		assert.True(t, d.IsClosed)
	})

	t.Run("error", func(t *testing.T) {
		d := mock.New()
		expected := errors.New("close failed")
		d.CloseErr = expected
		err := d.Close()
		assert.ErrorIs(t, err, expected)
		assert.False(t, d.IsClosed)
	})
}
