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

package file_test

import (
	"errors"
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/source/file"
)

func TestNew(t *testing.T) {
	mfs := fstest.MapFS{}
	l := slog.Default()

	s := file.New(mfs, file.WithExtension("txt"), file.WithLogger(l))
	assert.Equal(t, ".txt", s.Extension())
	assert.Equal(t, mfs, s.Directory())

	s2 := file.New(mfs, file.WithExtension(""))
	assert.Equal(t, file.DefaultExtension, s2.Extension())

	s3 := file.New(mfs, file.WithExtension(".csv"))
	assert.Equal(t, ".csv", s3.Extension())
}

func TestSource_Parse(t *testing.T) {
	s := file.New(fstest.MapFS{})

	tests := []struct {
		name string
		file string
		v    uint64
		desc string
		dir  migrate.Direction
		tx   bool
		err  error
	}{
		{
			"valid up",
			"01_init.up.sql",
			1,
			"init",
			migrate.Up,
			true,
			nil,
		},
		{
			"valid down",
			"002_add_users.down.sql",
			2,
			"add users",
			migrate.Down,
			true,
			nil,
		},
		{
			"valid up notx",
			"3_idx.up_notx.sql",
			3,
			"idx",
			migrate.Up,
			false,
			nil,
		},
		{
			"valid down notx",
			"04_idx.down_notx.sql",
			4,
			"idx",
			migrate.Down,
			false,
			nil,
		},
		{
			"bad ext",
			"01_init.up.txt",
			0,
			"",
			-1,
			false,
			file.ErrExtension,
		},
		{
			"no dot",
			"01_init_up.sql",
			0,
			"",
			-1,
			false,
			file.ErrMissingDirection,
		},
		{
			"bad dir",
			"01_init.foo.sql",
			0,
			"",
			0,
			false,
			file.ErrIllegalDirection,
		},
		{
			"no under",
			"01init.up.sql",
			0,
			"",
			0,
			false,
			file.ErrMissingSeparator,
		},
		{
			"empty v",
			"_init.up.sql",
			0,
			"",
			0,
			false,
			file.ErrInvalidVersion,
		},
		{
			"empty desc",
			"01_.up.sql",
			0,
			"",
			0,
			false,
			file.ErrInvalidDescription,
		},
		{
			"bad format",
			"abc_init.up.sql",
			0,
			"",
			0,
			false,
			file.ErrInvalidVersion,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, desc, dir, tx, err := s.Parse(tc.file)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.v, v)
				assert.Equal(t, tc.desc, desc)
				assert.Equal(t, tc.dir, dir)
				assert.Equal(t, tc.tx, tx)
			}
		})
	}
}

type walkErrFS struct{}

func (walkErrFS) Open(name string) (fs.File, error) {
	return nil, errors.New("forced walk error")
}

type readErrFS struct{ fs.FS }

func (r readErrFS) Open(name string) (fs.File, error) {
	if name == "01_bad.up.sql" {
		return nil, errors.New("forced read error")
	}
	return r.FS.Open(name)
}

func TestSource_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mfs := fstest.MapFS{
			"01_init.up.sql":       &fstest.MapFile{Data: []byte("UP1")},
			"02_add.down.sql":      &fstest.MapFile{Data: []byte("DOWN2")},
			"bad_format.up.sql":    &fstest.MapFile{Data: []byte("IGNOREME")},
			"subdir/03_sub.up.sql": &fstest.MapFile{Data: []byte("UP3")},
		}
		s := file.New(mfs)
		scripts, err := s.List()

		require.NoError(t, err)
		assert.Len(t, scripts, 3)

		assert.Equal(t, uint64(1), scripts[0].Version)
		assert.Equal(t, "UP1", string(scripts[0].Content))
		assert.Equal(t, migrate.Up, scripts[0].Direction)

		assert.Equal(t, uint64(2), scripts[1].Version)
		assert.Equal(t, uint64(3), scripts[2].Version)
	})

	t.Run("walkdir err", func(t *testing.T) {
		s := file.New(walkErrFS{})
		_, err := s.List()
		assert.ErrorContains(t, err, "failed to traverse migration directory")
	})

	t.Run("readfile err", func(t *testing.T) {
		mfs := fstest.MapFS{
			"01_bad.up.sql": &fstest.MapFile{Data: []byte("ERR")},
		}
		s := file.New(readErrFS{FS: mfs})
		_, err := s.List()
		assert.ErrorContains(t, err, "failed to read migration file")
	})
}
