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
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/source/file"
)

type mockWalkErrFS struct{}

func (mockWalkErrFS) Open(name string) (fs.File, error) {
	return nil, errors.New("forced walk error")
}

var _ fs.FS = mockWalkErrFS{}

type mockReadErrFS struct{ fs.FS }

func (r mockReadErrFS) Open(name string) (fs.File, error) {
	if name == "01_bad.up.sql" {
		return nil, errors.New("forced read error")
	}
	return r.FS.Open(name)
}

var _ fs.FS = mockReadErrFS{}

func TestNew(t *testing.T) {
	t.Parallel()

	mfs := fstest.MapFS{}
	l := slog.Default()

	s := file.New(mfs, file.WithExtension("txt"), file.WithLogger(l))
	if got, want := s.Extension(), ".txt"; got != want {
		t.Errorf("Extension() = %q; want %q", got, want)
	}
	if got, want := s.Directory(), mfs; !reflect.DeepEqual(got, want) {
		t.Errorf("Directory() = %v; want %v", got, want)
	}

	s2 := file.New(mfs, file.WithExtension(""))
	if got, want := s2.Extension(), file.DefaultExtension; got != want {
		t.Errorf("Extension() = %q; want %q", got, want)
	}

	s3 := file.New(mfs, file.WithExtension(".csv"))
	if got, want := s3.Extension(), ".csv"; got != want {
		t.Errorf("Extension() = %q; want %q", got, want)
	}
}

func TestSource_Parse(t *testing.T) {
	t.Parallel()

	s := file.New(fstest.MapFS{})

	tests := []struct {
		name        string
		give        string
		wantVersion uint64
		wantDesc    string
		wantDir     migrate.Direction
		wantTx      bool
		wantErr     error
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, desc, dir, tx, err := s.Parse(tt.give)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Parse(%q) err = %v; want %v", tt.give, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"Parse(%q) unexpected err = %v",
					tt.give, err,
				)
			}
			if v != tt.wantVersion {
				t.Errorf(
					"Parse(%q) version = %d; want %d",
					tt.give, v, tt.wantVersion,
				)
			}
			if desc != tt.wantDesc {
				t.Errorf(
					"Parse(%q) description = %q; want %q",
					tt.give, desc, tt.wantDesc,
				)
			}
			if dir != tt.wantDir {
				t.Errorf(
					"Parse(%q) direction = %v; want %v",
					tt.give, dir, tt.wantDir,
				)
			}
			if tx != tt.wantTx {
				t.Errorf(
					"Parse(%q) tx = %v; want %v",
					tt.give, tx, tt.wantTx,
				)
			}
		})
	}
}

func TestSource_List(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		mfs := fstest.MapFS{
			"01_init.up.sql":       &fstest.MapFile{Data: []byte("UP1")},
			"02_add.down.sql":      &fstest.MapFile{Data: []byte("DOWN2")},
			"04_idx.up_notx.sql":   &fstest.MapFile{Data: []byte("NOTX4")},
			"bad_format.up.sql":    &fstest.MapFile{Data: []byte("IGNOREME")},
			"subdir/03_sub.up.sql": &fstest.MapFile{Data: []byte("UP3")},
		}
		s := file.New(mfs)
		scripts, err := s.List()
		if err != nil {
			t.Fatalf("List() err = %v; want nil", err)
		}
		if got, want := len(scripts), 4; got != want {
			t.Fatalf("len(scripts) = %d; want %d", got, want)
		}

		// Verify first script
		if got, want := scripts[0].Version, uint64(1); got != want {
			t.Errorf("scripts[0].Version = %d; want %d", got, want)
		}
		if got, want := scripts[0].Description, "init"; got != want {
			t.Errorf("scripts[0].Description = %q; want %q", got, want)
		}
		if got, want := scripts[0].Direction, migrate.Up; got != want {
			t.Errorf("scripts[0].Direction = %v; want %v", got, want)
		}
		if !scripts[0].Tx {
			t.Errorf("scripts[0].Tx = false; want true")
		}
		if got, want := scripts[0].Path, "01_init.up.sql"; got != want {
			t.Errorf("scripts[0].Path = %q; want %q", got, want)
		}
		if !bytes.Equal(scripts[0].Content, []byte("UP1")) {
			t.Errorf("scripts[0].Content = %q; want %q", scripts[0].Content, "UP1")
		}

		// Verify direction logic
		if got, want := scripts[1].Direction, migrate.Down; got != want {
			t.Errorf("scripts[1].Direction = %v; want %v", got, want)
		}

		// Verify _notx flag
		if scripts[2].Tx {
			t.Errorf("scripts[2].Tx = true; want false")
		}

		// Verify subdirectory paths
		if got, want := scripts[3].Path, "subdir/03_sub.up.sql"; got != want {
			t.Errorf("scripts[3].Path = %q; want %q", got, want)
		}
	})

	t.Run("walkdir err", func(t *testing.T) {
		t.Parallel()
		s := file.New(mockWalkErrFS{})
		_, err := s.List()
		if err == nil {
			t.Errorf("List() did not return error")
		}
	})

	t.Run("readfile err", func(t *testing.T) {
		t.Parallel()
		mfs := fstest.MapFS{
			"01_bad.up.sql": &fstest.MapFile{Data: []byte("ERR")},
		}
		s := file.New(mockReadErrFS{FS: mfs})
		_, err := s.List()
		if err == nil {
			t.Errorf("List() did not return error")
		}
	})
}
